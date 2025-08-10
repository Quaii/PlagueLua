-- Spotify integration for Plague LUA
-- Fetches currently playing track via Spotify Web API using an access token

local ffi = require('ffi')
print('[Spotify] script loaded')
local ok_bit, bitlib = pcall(require, 'bit')
local bit = bit or (ok_bit and bitlib) or bit

-- Global Spotify info table, initialized early to avoid nil references
SpotifyInfo = SpotifyInfo or {
  title = '',
  artists = '',
  artists_list = {},
  duration_ms = 0,
  progress_ms = 0,
  is_playing = false,
  is_premium = false,
  artwork_url = '',
}
last_progress_update_at = last_progress_update_at or 0

-- =========================
-- Windows Shell (open URL)
-- =========================
ffi.cdef[[
  typedef void* HWND;
  typedef const char* LPCSTR;
  typedef const wchar_t* LPCWSTR;
  typedef uintptr_t HINSTANCE;
  HINSTANCE ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, int nShowCmd);
]]
local shell32 = ffi.load('shell32')

local function open_url(url)
  -- SW_SHOWNORMAL = 1
  shell32.ShellExecuteA(nil, "open", url, nil, nil, 1)
end

-- =========================
-- Clipboard (read token)
-- =========================
ffi.cdef[[
  typedef void* HANDLE;
  typedef unsigned int UINT;
  int OpenClipboard(void* hWndNewOwner);
  int CloseClipboard(void);
  int IsClipboardFormatAvailable(UINT format);
  HANDLE GetClipboardData(UINT uFormat);
  void* GlobalLock(HANDLE hMem);
  int GlobalUnlock(HANDLE hMem);
]]
local user32 = ffi.load('user32')
local kernel32 = ffi.load('kernel32')

-- =========================
-- URLMon (download to cache) + memcpy
-- =========================
ffi.cdef[[
  typedef void* LPUNKNOWN;
  typedef const char* LPCSTR;
  typedef unsigned long DWORD;
  long URLDownloadToCacheFileA(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD cchFileName, DWORD dwReserved, LPUNKNOWN lpfnCB);

  void* memcpy(void* dest, const void* src, size_t n);

  // File I/O
  void* CreateFileA(const char* lpFileName, unsigned long dwDesiredAccess, unsigned long dwShareMode, void* lpSecurityAttributes, unsigned long dwCreationDisposition, unsigned long dwFlagsAndAttributes, void* hTemplateFile);
  int WriteFile(void* hFile, const void* lpBuffer, unsigned long nNumberOfBytesToWrite, unsigned long* lpNumberOfBytesWritten, void* lpOverlapped);
  int CloseHandle(void* hObject);
]]
local ok_urlmon, urlmon = pcall(ffi.load, 'urlmon')
if not ok_urlmon then
  urlmon = nil
  print('[Spotify] urlmon.dll NOT found — cover art download disabled')
else
  print('[Spotify] urlmon.dll loaded')
end

local CF_UNICODETEXT = 13

local function utf16le_to_utf8(wstr)
  -- Convert UTF-16LE wchar_t* to Lua string (assumes ASCII/basic BMP chars)
  local bytes = {}
  local i = 0
  while true do
    local lo = ffi.cast("const uint16_t*", wstr)[i]
    if lo == 0 then break end
    if lo < 0x80 then
      bytes[#bytes+1] = string.char(lo)
    elseif lo < 0x800 then
      bytes[#bytes+1] = string.char(0xC0 + math.floor(lo / 0x40))
      bytes[#bytes+1] = string.char(0x80 + (lo % 0x40))
    else
      bytes[#bytes+1] = string.char(0xE0 + math.floor(lo / 0x1000))
      bytes[#bytes+1] = string.char(0x80 + (math.floor(lo / 0x40) % 0x40))
      bytes[#bytes+1] = string.char(0x80 + (lo % 0x40))
    end
    i = i + 1
  end
  return table.concat(bytes)
end

local function read_clipboard_text()
  if user32.IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 then
    return nil
  end
  if user32.OpenClipboard(nil) == 0 then
    return nil
  end
  local h = user32.GetClipboardData(CF_UNICODETEXT)
  local text = nil
  if h ~= nil then
    local p = kernel32.GlobalLock(h)
    if p ~= nil then
      text = utf16le_to_utf8(ffi.cast("const wchar_t*", p))
      kernel32.GlobalUnlock(h)
    end
  end
  user32.CloseClipboard()
  return text
end

-- =========================
-- WinINet (HTTPS GET)
-- =========================
ffi.cdef[[
  typedef void* HINTERNET;
  typedef unsigned long DWORD;
  typedef const char* LPCSTR;
  typedef void* LPVOID;
  typedef int BOOL;

  HINTERNET InternetOpenA(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
  HINTERNET InternetConnectA(HINTERNET, LPCSTR, unsigned short, LPCSTR, LPCSTR, DWORD, DWORD, DWORD);
  HINTERNET HttpOpenRequestA(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD);
  BOOL HttpSendRequestA(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
  BOOL HttpAddRequestHeadersA(HINTERNET, LPCSTR, DWORD, DWORD);
  BOOL InternetReadFile(HINTERNET, LPVOID, DWORD, DWORD*);
  BOOL InternetCloseHandle(HINTERNET);
  BOOL HttpQueryInfoA(HINTERNET, DWORD, LPVOID, DWORD*, DWORD*);
]]
local wininet = ffi.load('wininet')

-- WinINet constants
local INTERNET_OPEN_TYPE_DIRECT = 1
local INTERNET_SERVICE_HTTP = 3
local INTERNET_DEFAULT_HTTPS_PORT = 443
local INTERNET_FLAG_RELOAD = 0x80000000
local INTERNET_FLAG_SECURE = 0x00800000
local INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
local INTERNET_FLAG_KEEP_CONNECTION = 0x00400000

local HTTP_QUERY_STATUS_CODE = 19
local HTTP_QUERY_FLAG_NUMBER = 0x20000000

local function http_get_https(host, path, headers)
  local session = wininet.InternetOpenA("PlagueSpotify", INTERNET_OPEN_TYPE_DIRECT, nil, nil, 0)
  if session == nil then return nil, nil end
  local connect = wininet.InternetConnectA(session, host, INTERNET_DEFAULT_HTTPS_PORT, nil, nil, INTERNET_SERVICE_HTTP, 0, 0)
  if connect == nil then wininet.InternetCloseHandle(session) return nil, nil end

  local flags = bit.bor(INTERNET_FLAG_RELOAD, INTERNET_FLAG_SECURE, INTERNET_FLAG_NO_CACHE_WRITE, INTERNET_FLAG_KEEP_CONNECTION)
  local request = wininet.HttpOpenRequestA(connect, "GET", path, "HTTP/1.1", nil, nil, flags, 0)
  if request == nil then
    wininet.InternetCloseHandle(connect)
    wininet.InternetCloseHandle(session)
    return nil, nil
  end

  local header_str = headers or ""
  local ok = wininet.HttpSendRequestA(request, header_str, #header_str, nil, 0)
  if ok == 0 then
    wininet.InternetCloseHandle(request)
    wininet.InternetCloseHandle(connect)
    wininet.InternetCloseHandle(session)
    return nil, nil
  end

  -- Query numeric status code
  local status = ffi.new("DWORD[1]", 0)
  local status_len = ffi.new("DWORD[1]", ffi.sizeof(status))
  wininet.HttpQueryInfoA(request, bit.bor(HTTP_QUERY_STATUS_CODE, HTTP_QUERY_FLAG_NUMBER), status, status_len, nil)
  local status_code = tonumber(status[0])

  -- Read body
  local chunks = {}
  local buffer = ffi.new("uint8_t[4096]")
  local bytesRead = ffi.new("DWORD[1]", 0)
  while true do
    local read_ok = wininet.InternetReadFile(request, buffer, 4096, bytesRead)
    if read_ok == 0 then break end
    local n = tonumber(bytesRead[0])
    if n == 0 then break end
    chunks[#chunks+1] = ffi.string(buffer, n)
  end

  wininet.InternetCloseHandle(request)
  wininet.InternetCloseHandle(connect)
  wininet.InternetCloseHandle(session)

  return status_code, table.concat(chunks)
end

-- =========================
-- Minimal JSON decoder
-- =========================
-- Based on a compact JSON implementation for Lua (limited, sufficient for Spotify fields)
local function json_decode(str)
  local pos = 1
  local len = #str

  local function skip_ws()
    while true do
      local c = str:sub(pos,pos)
      if c == ' ' or c == '\n' or c == '\r' or c == '\t' then pos = pos + 1 else break end
    end
  end

  local function parse_value()
    skip_ws()
    local c = str:sub(pos,pos)
    if c == '"' then
      pos = pos + 1
      local s = {}
      while pos <= len do
        local ch = str:sub(pos,pos)
        if ch == '"' then
          pos = pos + 1
          return table.concat(s)
        elseif ch == '\\' then
          local n = str:sub(pos+1,pos+1)
          if n == '"' or n == '\\' or n == '/' then s[#s+1] = n; pos = pos + 2
          elseif n == 'b' then s[#s+1] = '\b'; pos = pos + 2
          elseif n == 'f' then s[#s+1] = '\f'; pos = pos + 2
          elseif n == 'n' then s[#s+1] = '\n'; pos = pos + 2
          elseif n == 'r' then s[#s+1] = '\r'; pos = pos + 2
          elseif n == 't' then s[#s+1] = '\t'; pos = pos + 2
          elseif n == 'u' then
            -- skip \uXXXX (basic support)
            local hex = str:sub(pos+2, pos+5)
            local code = tonumber(hex, 16) or 32
            if code < 0x80 then s[#s+1] = string.char(code)
            elseif code < 0x800 then s[#s+1] = string.char(0xC0 + math.floor(code/0x40), 0x80 + (code % 0x40))
            else s[#s+1] = string.char(0xE0 + math.floor(code/0x1000), 0x80 + (math.floor(code/0x40) % 0x40), 0x80 + (code % 0x40)) end
            pos = pos + 6
          else
            pos = pos + 1
          end
        else
          s[#s+1] = ch
          pos = pos + 1
        end
      end
      return table.concat(s)
    elseif c == '{' then
      pos = pos + 1
      local obj = {}
      skip_ws()
      if str:sub(pos,pos) == '}' then pos = pos + 1 return obj end
      while true do
        skip_ws()
        local key = parse_value()
        skip_ws()
        if str:sub(pos,pos) ~= ':' then return obj end
        pos = pos + 1
        local val = parse_value()
        obj[key] = val
        skip_ws()
        local ch = str:sub(pos,pos)
        if ch == '}' then pos = pos + 1 break end
        if ch ~= ',' then break end
        pos = pos + 1
      end
      return obj
    elseif c == '[' then
      pos = pos + 1
      local arr = {}
      skip_ws()
      if str:sub(pos,pos) == ']' then pos = pos + 1 return arr end
      local idx = 1
      while true do
        local val = parse_value()
        arr[idx] = val
        idx = idx + 1
        skip_ws()
        local ch = str:sub(pos,pos)
        if ch == ']' then pos = pos + 1 break end
        if ch ~= ',' then break end
        pos = pos + 1
      end
      return arr
    else
      -- number / literal
      local start = pos
      while pos <= len do
        local ch = str:sub(pos,pos)
        if ch:match("[,%]%}%s]") then break end
        pos = pos + 1
      end
      local token = str:sub(start, pos-1)
      if token == "true" then return true end
      if token == "false" then return false end
      if token == "null" then return nil end
      local num = tonumber(token)
      return num
    end
  end

  return parse_value()
end

-- =========================
-- Spotify logic
-- =========================
local spotify = {
  enabledVar = Menu.Checker('Spotify: Enabled', false),
  refreshVar = Menu.Slider('Spotify: Refresh (s)', 3, 1, 30),
  controlsVar = Menu.Checker('Spotify: Show controls', false),
  overlayShowVar = Menu.Checker('Spotify: Show screen overlay', false),
  overlayAttachVar = Menu.Combo('Spotify: Overlay position', 1, { 'Top of screen', 'Bottom of screen' }),
  timeFormatVar = Menu.Combo('Spotify: Time format', 0, { '24h', '12h' }),
  debugVar = Menu.Checker('Spotify: Debug cover art', false),
  testModalVar = Menu.Checker('Spotify: Test reauth modal', false),
  -- premium indicator removed per request
}

-- Accent color: fixed fallback (removed external accent fetching per request)

local access_token = nil
local refresh_token = nil
local last_fetch_time = 0
local font_loaded = false
local prev_left_down = false
local last_token_fetch_debug = 0
local panel_x, panel_y = 30, 120
local is_dragging_panel = false
local drag_offset_x, drag_offset_y = 0, 0
local overlay_alpha = 0.0 -- for fade animation
local FADE_SPEED = 5.0    -- alpha units per second (0..1)
local __sp_need_reauth = false
local __sp_prev_click = false
local force_controls_open = false
local modal_x, modal_y = nil, nil
local modal_dragging = false
local modal_drag_offx, modal_drag_offy = 0, 0
local __sp_suppress_reauth = false
local __sp_prev_enabled = nil

-- Persistent token storage
-- Resolve script directory to write data files next to this script
local function get_script_dir()
  -- Some environments disable the debug library. Guard it.
  local src = nil
  local ok, info = pcall(function()
    return (debug and debug.getinfo) and debug.getinfo(1, 'S') or nil
  end)
  if ok and info and info.source then
    src = info.source
  else
    return '.'
  end
  if src:sub(1,1) == '@' then src = src:sub(2) end
  src = src:gsub('\\','/')
  local dir = src:match('^(.*)/[^/]*$') or '.'
  return dir
end
local function join_path(a, b)
  if a == '' then return b end
  if a:sub(-1) == '/' then return a .. b end
  return a .. '/' .. b
end
local __sp_dir = get_script_dir()
print('[Spotify] Using data dir:', __sp_dir)

local token_file_path = join_path(__sp_dir, 'spotify_token.txt')
-- single combined token file: first line 'setup=0/1', following line is token
local function save_string_to_file(path, data)
  -- Try standard Lua I/O
  local ok, fh = pcall(io.open, path, 'wb')
  if ok and fh then
    fh:write(data or '')
    fh:close()
    return true
  end
  -- Fallback: WinAPI CreateFile/WriteFile
  local GENERIC_WRITE = 0x40000000
  local CREATE_ALWAYS = 2
  local handle = ffi.C.CreateFileA(path, GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, nil)
  if handle ~= nil and handle ~= ffi.cast('void*', -1) then
    local bytes = data or ''
    local written = ffi.new('unsigned long[1]', 0)
    ffi.C.WriteFile(handle, bytes, #bytes, written, nil)
    ffi.C.CloseHandle(handle)
    return true
  end
  return false
end

local function save_token()
  if not access_token or access_token == '' then return end
  local content = string.format('setup=1\n%s\n', access_token or '')
  save_string_to_file(token_file_path, content)
end
local function parse_token_content(data)
  data = data or ''
  data = data:gsub('\r','')
  local first = data:match('^([^\n]*)') or ''
  local rest = data:match('^[^\n]*\n(.*)$') or ''
  local setup = nil
  local token = ''
  local setupv = first:match('^%s*setup%s*=%s*([01])%s*$')
  if setupv then
    setup = tonumber(setupv)
    token = (rest:match('^%s*(.-)%s*$') or '')
  else
    token = (first:match('^%s*(.-)%s*$') or '')
  end
  return setup, token
end

local function load_token()
  access_token = nil
  local ok, fh = pcall(io.open, token_file_path, 'rb')
  local data = ''
  if ok and fh then
    data = fh:read('*a') or ''
    fh:close()
  else
    -- missing file: force setup
    __sp_setup_mode = true
    __sp_setup_step = 0
    return
  end
  local setup, token = parse_token_content(data)
  if token and #token > 0 then
    access_token = token
  else
    access_token = nil
  end
  if setup == nil then
    __sp_setup_mode = (access_token == nil)
    __sp_setup_step = 0
  else
    __sp_setup_mode = (setup == 0)
    if __sp_setup_mode then __sp_setup_step = 0 end
  end
end
load_token()

-- If no token is present at load time, force setup regardless of setup file
-- Keep previously set setup flags; do not redeclare or reset them here

local function url_encode(str)
  return (tostring(str or ''):gsub("[^%w%-_%.~]", function(ch)
    return string.format('%%%02X', string.byte(ch))
  end))
end

local function try_read_file(path)
  local ok, fh = pcall(io.open, path, 'rb')
  if not ok or not fh then return nil end
  local data = fh:read('*a')
  fh:close()
  return data
end

local function test_token_valid()
  if not access_token or access_token == '' then
    print('[Spotify] No access token set; cannot test')
    return
  end
  local host = 'api.spotify.com'
  local qs = 'access_token=' .. url_encode(access_token)
  local path = '/v1/me?' .. qs
  local headers = 'Accept: application/json\r\nHost: api.spotify.com\r\nUser-Agent: PlagueSpotify/1.0\r\nConnection: Keep-Alive\r\n'
  local s, b = http_get_https(host, path, headers)
  -- debug suppressed
  if s == 200 and b then
    local ok, obj = pcall(json_decode, b)
    if ok and type(obj) == 'table' then
      local id = obj.id or obj.display_name or '(no id)'
      if type(obj.product) == 'string' then
        local is_premium = (obj.product == 'premium')
        print('[Spotify] Account product:', tostring(obj.product), is_premium and '(Premium)' or '(Not premium)')
      else
        print('[Spotify] Account product not available (missing user-read-private scope)')
      end
      print('[Spotify] Token valid for user: ' .. tostring(id))
      return true
    end
    print('[Spotify] Token valid; failed to parse user JSON')
    return true
  end
  if s == 401 then
    -- Try Bearer header
    local path2 = '/v1/me'
    local headers2 = 'Authorization: Bearer ' .. access_token .. '\r\nAccept: application/json\r\nHost: api.spotify.com\r\nUser-Agent: PlagueSpotify/1.0\r\nConnection: Keep-Alive\r\n'
    local s2, b2 = http_get_https(host, path2, headers2)
    -- debug suppressed
    if s2 == 200 then
      local ok, obj = pcall(json_decode, b2 or '')
      local id = ok and type(obj) == 'table' and (obj.id or obj.display_name) or '(no id)'
      if ok and type(obj) == 'table' then
        if type(obj.product) == 'string' then
          local is_premium = (obj.product == 'premium')
          print('[Spotify] Account product:', tostring(obj.product), is_premium and '(Premium)' or '(Not premium)')
        else
          print('[Spotify] Account product not available (missing user-read-private scope)')
        end
      end
      print('[Spotify] Token valid (Bearer) for user: ' .. tostring(id))
      return true
    end
    -- Try automatic refresh exchange and re-test
    if refresh_token and #refresh_token > 0 then
      print('[Spotify] Attempting refresh exchange after 401...')
      if exchange_refresh_token(refresh_token) then
        -- Retry test with new access token
        local qs2 = 'access_token=' .. url_encode(access_token)
        local path3 = '/v1/me?' .. qs2
        local headers3 = 'Accept: application/json\r\nHost: api.spotify.com\r\nUser-Agent: PlagueSpotify/1.0\r\nConnection: Keep-Alive\r\n'
        local s3, b3 = http_get_https(host, path3, headers3)
        print(string.format('[Spotify] RETEST GET %s -> %s', path3, tostring(s3)))
        if s3 == 200 then
          print('[Spotify] Token valid after refresh exchange')
          return true
        end
      end
    end
    if b2 and #b2 > 0 then
      print('[Spotify] Error body (Bearer): ' .. string.sub(b2, 1, 256))
    end
  end
  print('[Spotify] Token test failed; status ' .. tostring(s))
  if b and #b > 0 then
    print('[Spotify] Error body: ' .. string.sub(b, 1, 256))
  end
  return false
end

local function classify_token(token)
  if not token or #token == 0 then return nil end
  if token:match('^BQ') then return 'access' end
  if token:match('^AQ') then return 'refresh' end
  return nil
end

local function exchange_refresh_token(refresh)
  local host = 'spotify.stbrouwers.cc'
  local path = '/refresh_token?refresh_token=' .. url_encode(refresh)
  local headers = 'Accept: application/json\r\nHost: spotify.stbrouwers.cc\r\nUser-Agent: PlagueSpotify/1.0\r\nConnection: Keep-Alive\r\n'
  local s, b = http_get_https(host, path, headers)
  -- debug suppressed
  if s == 200 and b and #b > 0 then
    local ok, obj = pcall(json_decode, b)
    if ok and type(obj) == 'table' and type(obj.access_token) == 'string' then
      access_token = obj.access_token
      save_token()
      print('[Spotify] Exchanged refresh token -> access token set')
      return true
    else
      print('[Spotify] Failed to parse refresh response')
    end
  else
    if b and #b > 0 then
      print('[Spotify] Refresh exchange failed; body: ' .. string.sub(b, 1, 256))
    else
      print('[Spotify] Refresh exchange failed; status ' .. tostring(s))
    end
  end
  return false
end

local function is_point_in_rect(px, py, x, y, w, h)
  return px >= x and py >= y and px <= x + w and py <= y + h
end

local function draw_button(label, x, y, w, h, pressed)
  local fill = pressed and Color(29, 29, 29, 255) or Color(18, 18, 18, 255)
  local outline = Color(29, 29, 29, 255)
  Renderer.DrawRectFilled(Vector2D(x, y), Vector2D(x + w, y + h), fill, 0)
  Renderer.DrawRect(Vector2D(x, y), Vector2D(x + w, y + h), outline, 0)
  local text_w = (#label) * 8
  local text_h = 16
  local text_x = x + math.floor((w - text_w) / 2)
  local text_y = y + math.floor((h - text_h) / 2)
  -- Button text color 949494
  Renderer.DrawText('Verdana', label, Vector2D(text_x, text_y), false, false, Color(0x94, 0x94, 0x94, 255))
end

local function hex_to_color(hex, alpha)
  local h = tostring(hex or ""):gsub("#", "")
  if #h == 3 then
    -- e.g. fff
    local r = tonumber(string.rep(h:sub(1,1),2), 16) or 0
    local g = tonumber(string.rep(h:sub(2,2),2), 16) or 0
    local b = tonumber(string.rep(h:sub(3,3),2), 16) or 0
    return Color(r, g, b, alpha or 255)
  end
  if #h < 6 then h = string.rep("0", 6 - #h) .. h end
  local r = tonumber(h:sub(1,2), 16) or 0
  local g = tonumber(h:sub(3,4), 16) or 0
  local b = tonumber(h:sub(5,6), 16) or 0
  return Color(r, g, b, alpha or 255)
end

local function get_accent_color()
  return hex_to_color('5B86C6')
end

-- Attempt to download bytes from an https URL and build a texture
local artwork_cache = {
  current_url = nil,
  texture = nil,
}

local function download_to_cache(url)
  if not urlmon then
    if spotify.debugVar and spotify.debugVar:GetBool() then
      print('[CoverArt] urlmon.dll not available; cannot download artwork')
    end
    return nil, 'no_urlmon'
  end
  local buf = ffi.new('char[?]', 260)
  local hr = urlmon.URLDownloadToCacheFileA(nil, url, buf, 260, 0, nil)
  if hr ~= 0 then
    if spotify.debugVar and spotify.debugVar:GetBool() then
      print(string.format('[CoverArt] URLDownloadToCacheFileA failed: 0x%X', tonumber(hr)))
    end
    return nil, string.format('0x%X', tonumber(hr))
  end
  local path = ffi.string(buf)
  if spotify.debugVar and spotify.debugVar:GetBool() then
    print('[CoverArt] Cached to:', path)
  end
  return path
end

local function read_all_bytes(path)
  local f = io.open(path, 'rb')
  if not f then return nil end
  local data = f:read('*a')
  f:close()
  return data
end

-- Base64 encoder for binary strings
local _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function to_base64(bin)
  local t, n = {}, #bin
  local i = 1
  while i <= n do
    local a = string.byte(bin, i)     or 0
    local b = string.byte(bin, i + 1) or 0
    local c = string.byte(bin, i + 2) or 0
    local triple = a * 65536 + b * 256 + c
    local s1 = math.floor(triple / 262144) % 64 + 1
    local s2 = math.floor(triple /   4096) % 64 + 1
    local s3 = math.floor(triple /     64) % 64 + 1
    local s4 =                      triple % 64 + 1
    if i + 1 > n then
      t[#t+1] = _b64chars:sub(s1,s1) .. _b64chars:sub(s2,s2) .. '=='
    elseif i + 2 > n then
      t[#t+1] = _b64chars:sub(s1,s1) .. _b64chars:sub(s2,s2) .. _b64chars:sub(s3,s3) .. '='
    else
      t[#t+1] = _b64chars:sub(s1,s1) .. _b64chars:sub(s2,s2) .. _b64chars:sub(s3,s3) .. _b64chars:sub(s4,s4)
    end
    i = i + 3
  end
  return table.concat(t)
end

local function create_texture_from_blob(blob, target_size)
  if spotify.debugVar and spotify.debugVar:GetBool() then
    print('[CoverArt] Blob size:', #blob)
  end
  -- Prefer Base64 path; keep string alive to avoid GC issues
  if Renderer.CreateTextureFromBase64 then
    local b64 = to_base64(blob)
    local ok_b64, tex_b64 = pcall(function()
      return Renderer.CreateTextureFromBase64(b64, Vector2D(target_size, target_size))
    end)
    if ok_b64 and tex_b64 then
      return tex_b64, b64
    end
    if spotify.debugVar and spotify.debugVar:GetBool() then
      print('[CoverArt] CreateTextureFromBase64 failed')
    end
  end
  -- Fallback to bytes API if Base64 not available
  local ok_str, tex_str = pcall(function()
    return Renderer.CreateTextureFromBytes(blob, Vector2D(target_size, target_size))
  end)
  if ok_str and tex_str then return tex_str, nil end
  local arr = ffi.new('uint8_t[?]', #blob)
  ffi.C.memcpy(arr, blob, #blob)
  local ok_ffi, tex_ffi = pcall(function()
    return Renderer.CreateTextureFromBytes(arr, Vector2D(target_size, target_size))
  end)
  if ok_ffi and tex_ffi then return tex_ffi, nil end
  if spotify.debugVar and spotify.debugVar:GetBool() then
    print('[CoverArt] Texture creation failed for all input types')
  end
  return nil, nil
end

local function split_https_url(u)
  local host, path = tostring(u or ''):match('^https://([^/]+)(/.*)$')
  if not host then
    host, path = tostring(u or ''):match('^http://([^/]+)(/.*)$')
  end
  return host, path
end

local function http_get_binary(url)
  local host, path = split_https_url(url)
  if not host or not path then return nil, 'bad_url' end
  local status, body = http_get_https(host, path, 'Accept: */*\r\nConnection: Keep-Alive\r\n')
  if status ~= 200 or not body or #body == 0 then
    return nil, 'http_' .. tostring(status)
  end
  return body
end

local CoverArt = {
  _cache = {},
  _order = {},
  _max = 20,
  _token = 0,
  _inflight = {},
  _runner = {},
}

local function lru_touch(self, url)
  self._cache[url].last_used = os.clock()
  self._order = {}
  for u, v in pairs(self._cache) do
    table.insert(self._order, { u = u, t = v.last_used })
  end
  table.sort(self._order, function(a,b) return a.t > b.t end)
end

local function lru_evict(self)
  while #self._order > self._max do
    local victim = self._order[#self._order].u
    self._cache[victim] = nil
    table.remove(self._order)
  end
end

function CoverArt:get(url)
  local e = self._cache[url]
  if e and e.tex then
    lru_touch(self, url)
    return e.tex
  end
  return nil
end

function CoverArt:set_current(url, target_size)
  self._token = self._token + 1
  local my_token = self._token
  if not url or url == '' then return nil end
  local t = self:get(url)
  if t then return t end
  if self._inflight[url] then return nil end
  self._inflight[url] = true

  local co
  co = coroutine.create(function()
    local bytes, err = http_get_binary(url)
    if my_token ~= self._token then self._inflight[url] = nil return end
    if not bytes or #bytes == 0 then
      if spotify.debugVar and spotify.debugVar:GetBool() then
        print('[CoverArt] http_get_binary failed:', tostring(err))
      end
      self._inflight[url] = nil
      return
    end
    local tex, b64 = create_texture_from_blob(bytes, target_size)
    if tex then
      self._cache[url] = { tex = tex, last_used = os.clock(), _b64 = b64 }
      lru_touch(self, url)
      lru_evict(self)
    else
      if spotify.debugVar and spotify.debugVar:GetBool() then
        print('[CoverArt] texture creation returned nil')
      end
    end
    self._inflight[url] = nil
  end)
  table.insert(self._runner, co)
  return nil
end

function CoverArt:update()
  for i = #self._runner, 1, -1 do
    local co = self._runner[i]
    if coroutine.status(co) == 'dead' then
      table.remove(self._runner, i)
    else
      local ok, err = coroutine.resume(co)
      if not ok then
        if spotify.debugVar and spotify.debugVar:GetBool() then
          print('[CoverArt] coroutine error:', tostring(err))
        end
        table.remove(self._runner, i)
      end
    end
  end
end

local function ensure_artwork_texture(target_size)
  local url = SpotifyInfo and SpotifyInfo.artwork_url or ''
  if not url or url == '' then
    return nil
  end
  local t = CoverArt:get(url)
  if t then return t end
  CoverArt:set_current(url, target_size)
  return nil
end

local function fetch_currently_playing()
  if not access_token or access_token == '' then
    if spotify.enabledVar and spotify.enabledVar:GetBool() then
      __sp_setup_mode = true
      __sp_setup_step = 0
    end
    return nil, 'No access token'
  end
  local host = 'api.spotify.com'

  -- Prefer query parameter token (as per reference script behavior)
  local access_qs = 'access_token=' .. url_encode(access_token)

  -- Try /me/player first
  local path = '/v1/me/player?market=from_token&' .. access_qs
  local headers = 'Accept: application/json\r\n'
  local status, body = http_get_https(host, path, headers)
  -- debug suppressed
  if not status then return nil, 'Request failed' end
  if status == 200 then return body, nil end
  if status == 204 then return nil, 'No content (nothing playing)' end
  if status == 401 then
    -- Fallback to Authorization header once in case the server rejects query param format
    local path2 = '/v1/me/player?market=from_token'
    local headers2 = 'Authorization: Bearer ' .. access_token .. '\r\nAccept: application/json\r\n'
    local s2, b2 = http_get_https(host, path2, headers2)
    -- debug suppressed
    if s2 == 200 then return b2, nil end
    __sp_need_reauth = true
    return nil, 'Unauthorized (invalid/expired token)'
  end
  -- Fallback to currently-playing
  local path3 = '/v1/me/player/currently-playing?market=from_token&' .. access_qs
  local s3, b3 = http_get_https(host, path3, headers)
  -- debug suppressed
  if s3 == 200 then return b3, nil end
  if s3 == 204 then return nil, 'No content (nothing playing)' end
  if s3 == 401 then
    if not __sp_suppress_reauth then __sp_need_reauth = true end
    return nil, 'Unauthorized (invalid/expired token)'
  end
  return nil, 'HTTP ' .. tostring(status)
end

local function join_artists(artists)
  if type(artists) ~= 'table' then return '' end
  local names = {}
  for i = 1, #artists do
    local a = artists[i]
    if type(a) == 'table' and type(a.name) == 'string' then
      names[#names+1] = a.name
    end
  end
  return table.concat(names, ', ')
end

local function parse_spotify_payload(json)
  local ok, data = pcall(json_decode, json)
  if not ok or type(data) ~= 'table' then return nil end
  local item = data.item
  if type(item) ~= 'table' then return nil end
  local title = item.name or ''
  local artists_tbl = item.artists or {}
  local artists = join_artists(artists_tbl)
  local duration_ms = tonumber(item.duration_ms) or 0
  local progress_ms = tonumber(data.progress_ms) or 0
  local is_playing = data.is_playing == true
  local premium = false
  if type(data.device) == 'table' and type(data.device.product) == 'string' then
    -- heuristic: product might indicate premium; if not available, fallback on capabilities
    premium = true
  elseif type(data.device) == 'table' and data.device.supports_playback_speed then
    premium = true
  end
  local artwork = ''
  if type(item.album) == 'table' and type(item.album.images) == 'table' and #item.album.images > 0 then
    local img = item.album.images[1]
    if type(img) == 'table' and type(img.url) == 'string' then artwork = img.url end
  end
  return {
    title = title,
    artists = artists,
    artists_list = artists_tbl,
    duration_ms = duration_ms,
    progress_ms = progress_ms,
    is_playing = is_playing,
    is_premium = premium,
    artwork = artwork,
  }
end

local function ms_to_mmss(ms)
  local total = math.floor(ms / 1000)
  local m = math.floor(total / 60)
  local s = total % 60
  return string.format('%d:%02d', m, s)
end

local function format_time(now, use12h)
  local t = os.date("*t", now)
  if use12h then
    local ampm = (t.hour >= 12) and 'PM' or 'AM'
    local h = t.hour % 12
    if h == 0 then h = 12 end
    return string.format('%02d:%02d %s', h, t.min, ampm)
  else
    return string.format('%02d:%02d', t.hour, t.min)
  end
end

-- Store last known info for external use and smooth progress rendering (use global defined at top)
-- Removed duplicate local declaration to avoid shadowing

function Spotify_GetInfo()
  return SpotifyInfo
end

local function update_spotify()
  local now = Globals.GetCurrentTime()
  local interval = spotify.refreshVar:GetInt()
  if now - last_fetch_time < interval then return end
  last_fetch_time = now

  local body, err = fetch_currently_playing()
  if not body then
    if err then print('[Spotify] ' .. err) end
    return
  end
  local info = parse_spotify_payload(body)
  if not info then
    print('[Spotify] Failed to parse response')
    return
  end
  SpotifyInfo.title = info.title or ''
  SpotifyInfo.artists = info.artists or ''
  SpotifyInfo.artists_list = info.artists_list or {}
  SpotifyInfo.duration_ms = info.duration_ms or 0
  SpotifyInfo.progress_ms = info.progress_ms or 0
  SpotifyInfo.is_playing = info.is_playing or false
  SpotifyInfo.is_premium = info.is_premium or false
  SpotifyInfo.artwork_url = info.artwork or ''
  last_progress_update_at = now
  -- Logging of current track suppressed to avoid console spam
  if spotify.premiumVar then
    -- Reflect premium state in a dummy checkbox (visual only)
    -- Some environments' MenuVar don't allow programmatic set; this may be visual-only
    if SpotifyInfo.is_premium then
      -- best-effort: draw a small text since checkbox may not be settable
    end
  end
end

local function OnRenderer()
  if not __sp_once then print('[Spotify] OnRenderer active') __sp_once = true end
  -- Ensure font is loaded before any text drawing (modals, overlay, controls)
  if not font_loaded then
    pcall(function()
      Renderer.LoadFontFromFile('Verdana', 'verdana', 16, true)
    end)
    font_loaded = true
  end
  -- Fetch loop
  if spotify.enabledVar:GetBool() then
    -- if token file missing or token empty, force setup and skip fetch
    local tok_ok, tok_fh = pcall(io.open, token_file_path, 'rb')
    local need_setup = true
    if tok_ok and tok_fh then
      local data = tok_fh:read('*a') or ''
      tok_fh:close()
      local _, tok = parse_token_content(data)
      need_setup = (not tok or #tok == 0)
    end
    if need_setup then
      __sp_setup_mode = true
      if __sp_setup_step < 0 then __sp_setup_step = 0 end
    else
      update_spotify()
    end
  end

  -- Track enable edge to clear reauth suppression
  local cur_enabled = spotify.enabledVar and spotify.enabledVar:GetBool()
  if __sp_prev_enabled == nil then __sp_prev_enabled = cur_enabled end
  if cur_enabled ~= __sp_prev_enabled then
    __sp_suppress_reauth = false
    __sp_prev_enabled = cur_enabled
  end

  -- Locally advance progress for smoother UI
  if SpotifyInfo and SpotifyInfo.is_playing and SpotifyInfo.duration_ms > 0 and last_progress_update_at and last_progress_update_at > 0 then
    local now = Globals.GetCurrentTime()
    local delta_ms = math.max(0, (now - last_progress_update_at) * 1000)
    last_progress_update_at = now
    SpotifyInfo.progress_ms = math.min(SpotifyInfo.duration_ms, (SpotifyInfo.progress_ms or 0) + delta_ms)
  end

  -- Pump cover art loader (not in draw-only path)
  CoverArt:update()

  -- Menu overlay: buttons (toggleable)
  if Input.IsMenuOpen() and ((spotify.controlsVar and spotify.controlsVar:GetBool()) or force_controls_open) then
    -- Top-left of the whole panel (draggable)
    panel_x = panel_x or 30
    panel_y = panel_y or 120
    local px, py = panel_x, panel_y
    -- 1) Base rectangle 250x260, fill 0e0e0e, r=0, no outline
    local base_w, base_h = 250, 260
    Renderer.DrawRectFilled(Vector2D(px, py), Vector2D(px + base_w, py + base_h), hex_to_color('0E0E0E'), 0)

    -- 2) Inner rectangle 246x256, centered inside, fill 0e0e0e, outline 1D1D1D, r=0
    local inner_w, inner_h = 246, 256
    local ix = px + math.floor((base_w - inner_w) / 2)
    local iy = py + math.floor((base_h - inner_h) / 2)
    Renderer.DrawRectFilled(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('0E0E0E'), 0)
    Renderer.DrawRect(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('1D1D1D'), 0)

    -- 3) Header rectangle 246x23 at top of inner, fill 151515
    local header_h = 23
    local header_x1, header_y1 = ix, iy
    local header_x2, header_y2 = ix + inner_w, iy + header_h
    Renderer.DrawRectFilled(Vector2D(header_x1, header_y1), Vector2D(header_x2, header_y2), hex_to_color('151515'), 0)
    -- Header text smaller and left-aligned
    local header_label = 'Spotify Controls'
    local header_text_x = ix + 6
    local header_text_y = iy + 3
    Renderer.DrawText('Verdana', header_label, Vector2D(header_text_x, header_text_y), false, false, Color(220, 220, 220, 255))

    -- 4) Divider line 246x1 using accent color directly below header
    local divider_y = iy + header_h
    local accent = get_accent_color()
    Renderer.DrawRectFilled(Vector2D(ix, divider_y), Vector2D(ix + inner_w, divider_y + 1), accent, 0)

    -- 5) Content rectangle 224x210, centered, 11px padding from divider and bottom, fill 151515, outline 1D1D1D
    local content_w, content_h = 224, 210
    local content_x = ix + math.floor((inner_w - content_w) / 2)
    local content_y = divider_y + 11
    Renderer.DrawRectFilled(Vector2D(content_x, content_y), Vector2D(content_x + content_w, content_y + content_h), hex_to_color('151515'), 0)
    Renderer.DrawRect(Vector2D(content_x, content_y), Vector2D(content_x + content_w, content_y + content_h), hex_to_color('1D1D1D'), 0)

    -- Buttons inside content area (184x23 centered)
    local bw, bh = 184, 23
    local gap = 8
    local pad_side = 19
    local pad_top = 19
    local bx = content_x + math.floor((content_w - bw) / 2)
    local by = content_y + pad_top
    local buttons = {
      { label = 'Open website' },
      { label = 'Set access token' },
      { label = 'Use refresh token' },
      { label = 'Test token' },
    }

    -- Read mouse state for pressed effect while drawing
    local dmouse = Input.GetCursorPos()
    local dmx, dmy = dmouse.x, dmouse.y
    local dLeft = Input.GetKeyDown(1)
    for i, b in ipairs(buttons) do
      local yrow = by + (i - 1) * (bh + gap)
      local inside = (dmx >= bx and dmx <= bx + bw and dmy >= yrow and dmy <= yrow + bh)
      draw_button(b.label, bx, yrow, bw, bh, dLeft and inside)
      b._x, b._y, b._w, b._h = bx, yrow, bw, bh
    end

    local mouse = Input.GetCursorPos()
    local mx, my = mouse.x, mouse.y
    local leftDown = Input.GetKeyDown(1)

    -- Dragging logic via header
    if leftDown and not prev_left_down then
      if mx >= header_x1 and mx <= header_x2 and my >= header_y1 and my <= header_y2 then
        is_dragging_panel = true
        drag_offset_x = mx - px
        drag_offset_y = my - py
      end
    end
    if is_dragging_panel then
      if leftDown then
        panel_x = mx - drag_offset_x
        panel_y = my - drag_offset_y
      else
        is_dragging_panel = false
      end
    end

    local function normalize_token(raw)
      local txt = tostring(raw or '')
      txt = txt:gsub('^%s+', ''):gsub('%s+$', '')
      txt = txt:gsub('^"(.-)"$', '%1') -- strip surrounding quotes
      txt = txt:gsub("^Bearer%s+", "") -- strip Bearer prefix
      -- If looks like a URL or contains access_token=, extract it
      local in_qs = txt:match('access_token=([^&%s]+)')
      if in_qs then return in_qs end
      -- If JSON
      if txt:find('{', 1, true) then
        local ok, obj = pcall(json_decode, txt)
        if ok and type(obj) == 'table' then
          if type(obj.access_token) == 'string' and #obj.access_token > 0 then
            return obj.access_token
          end
          if type(obj.token) == 'string' and #obj.token > 0 then
            return obj.token
          end
        end
      end
      return txt
    end

    if leftDown and not prev_left_down then
      if is_point_in_rect(mx, my, buttons[1]._x, buttons[1]._y, buttons[1]._w, buttons[1]._h) then
        open_url('https://spotify.stbrouwers.cc')
      elseif is_point_in_rect(mx, my, buttons[2]._x, buttons[2]._y, buttons[2]._w, buttons[2]._h) then
        local clip = read_clipboard_text()
        if clip and #clip > 0 then
          local token = normalize_token(clip)
          if token and #token > 0 then
            local kind = classify_token(token)
            if kind == 'refresh' then
              print('[Spotify] Clipboard contains a refresh token; exchanging...')
              refresh_token = token
              exchange_refresh_token(refresh_token)
            else
              access_token = token
              save_token()
              print('[Spotify] Access token set from clipboard')
            end
          else
            print('[Spotify] Clipboard text did not contain a token')
          end
        else
          print('[Spotify] Clipboard is empty or not text')
        end
      elseif is_point_in_rect(mx, my, buttons[3]._x, buttons[3]._y, buttons[3]._w, buttons[3]._h) then
        -- Clipboard contains refresh token -> exchange for access token
        local clip = read_clipboard_text()
        clip = clip and clip:gsub('^%s+', ''):gsub('%s+$', '') or ''
        if clip == '' then
          print('[Spotify] Clipboard is empty, expected refresh token')
        else
          local host = 'spotify.stbrouwers.cc'
          local path = '/refresh_token?refresh_token=' .. url_encode(clip)
          local headers = 'Accept: application/json\r\n'
          local s, b = http_get_https(host, path, headers)
          print(string.format('[Spotify] GET %s -> %s', path, tostring(s)))
          if s == 200 and b and #b > 0 then
            local ok, obj = pcall(json_decode, b)
            if ok and type(obj) == 'table' and type(obj.access_token) == 'string' then
              refresh_token = clip
              access_token = obj.access_token
              save_token()
              print('[Spotify] Exchanged refresh token -> access token set')
            else
              print('[Spotify] Failed to parse refresh response')
            end
          else
            print('[Spotify] Refresh exchange failed; status ' .. tostring(s))
          end
        end
      elseif is_point_in_rect(mx, my, buttons[4]._x, buttons[4]._y, buttons[4]._w, buttons[4]._h) then
        test_token_valid()
      end
    end
    prev_left_down = leftDown

    local status = access_token and (#access_token > 0) and 'Token: SET' or 'Token: NOT SET'
    local status_color = get_accent_color()
    local status_label = status
    -- place next to last button with same vertical spacing
    local last_btn_y = by + (#buttons - 1) * (bh + gap)
    local status_x = bx
    local status_y = last_btn_y + bh + gap
    Renderer.DrawText('Verdana', status_label, Vector2D(status_x, status_y), false, false, status_color)
  end

  -- Screen-anchored overlay bar (independent toggle, but only visible when menu is open)
  -- Fade in/out alpha for overlay
  local overlay_enabled = spotify.overlayShowVar and spotify.overlayShowVar:GetBool()
  -- Overlay options always present (dynamic creation removed to avoid environment crash)
  local target_alpha = (Input.IsMenuOpen() and overlay_enabled) and 1.0 or 0.0
  do
    local dt = Globals.GetFrameTime() or 0.016
    if target_alpha > overlay_alpha then
      overlay_alpha = math.min(1.0, overlay_alpha + dt * FADE_SPEED)
    else
      overlay_alpha = math.max(0.0, overlay_alpha - dt * FADE_SPEED)
    end
  end

  if spotify.overlayShowVar and spotify.overlayShowVar:GetBool() and (Input.IsMenuOpen() or overlay_alpha > 0.001) then
    local screen = Renderer.GetScreenSize()
    local sw, sh = screen.x, screen.y
    local attach_top = spotify.overlayAttachVar:GetInt() == 0
    local margin = 30
    local outer_x = margin
    local outer_w = math.max(0, sw - margin * 2)
    local outer_h = 60
    local outer_y = attach_top and (margin) or (sh - margin - outer_h)
    local baseA = math.floor(overlay_alpha * 255)
    Renderer.DrawRectFilled(Vector2D(outer_x, outer_y), Vector2D(outer_x + outer_w, outer_y + outer_h), Color(0x0E, 0x0E, 0x0E, baseA), 0)

    -- Inner (overlay frame) rect: -2 width/height (i.e., 2px less in both dims)
    local inner_x = outer_x + 1
    local inner_y = outer_y + 1
    local inner_w2 = outer_w - 2
    local inner_h2 = outer_h - 2 -- 58
    Renderer.DrawRectFilled(Vector2D(inner_x, inner_y), Vector2D(inner_x + inner_w2, inner_y + inner_h2), Color(0x0E, 0x0E, 0x0E, baseA), 0)
    Renderer.DrawRect(Vector2D(inner_x, inner_y), Vector2D(inner_x + inner_w2, inner_y + inner_h2), Color(0x1D, 0x1D, 0x1D, baseA), 0)

    -- Main content rect: width = outer_w - 14, height = 44, centered horizontally
    local main_w, main_h = outer_w - 14, 44
    local main_x = outer_x + math.floor((outer_w - main_w) / 2)
    local main_y = outer_y + math.floor((outer_h - main_h) / 2)
    Renderer.DrawRectFilled(Vector2D(main_x, main_y), Vector2D(main_x + main_w, main_y + main_h), Color(0x15, 0x15, 0x15, baseA), 0)
    Renderer.DrawRect(Vector2D(main_x, main_y), Vector2D(main_x + main_w, main_y + main_h), Color(0x1D, 0x1D, 0x1D, baseA), 0)

    -- Content layout inside main rect
    local pad = 5
    local accent = get_accent_color()

    -- Cover rect 33x33 with 5px padding from left and centered vertically in main
    local cover_size = 33
    local cover_x = main_x + pad
    local cover_y = main_y + math.floor((main_h - cover_size) / 2)
    -- Try to draw artwork if available; otherwise placeholder
    local ok_art, art_tex = pcall(ensure_artwork_texture, cover_size)
    if ok_art and art_tex then
      pcall(function()
        -- Draw rotated 180° by using negative size from bottom-right corner
        Renderer.DrawTexture(art_tex, Vector2D(cover_x + cover_size, cover_y + cover_size), Vector2D(-cover_size, -cover_size))
        Renderer.DrawRect(Vector2D(cover_x, cover_y), Vector2D(cover_x + cover_size, cover_y + cover_size), Color(0x1D, 0x1D, 0x1D, baseA), 0)
      end)
    else
      Renderer.DrawRectFilled(Vector2D(cover_x, cover_y), Vector2D(cover_x + cover_size, cover_y + cover_size), Color(0x22, 0x22, 0x22, baseA), 0)
      Renderer.DrawRect(Vector2D(cover_x, cover_y), Vector2D(cover_x + cover_size, cover_y + cover_size), Color(0x1D, 0x1D, 0x1D, baseA), 0)
    end

    -- Text area to the right of cover (padding 9)
    local text_x = cover_x + cover_size + 9
    local title = SpotifyInfo.title or ''
    local artists = SpotifyInfo.artists or ''
    Renderer.DrawText('Verdana', title, Vector2D(text_x, main_y + 6), false, false, Color(220, 220, 220, baseA)) -- size approximated
    Renderer.DrawText('Verdana', artists, Vector2D(text_x, main_y + 20), false, false, Color(0x94, 0x94, 0x94, baseA))

    -- Progress bar (350x1) centered horizontally in main
    local bar_w, bar_h = 350, 1
    local bar_x = main_x + math.floor((main_w - bar_w) / 2)
    local bar_y = main_y + math.floor(main_h / 2)
    local accentA = Color(accent.r, accent.g, accent.b, baseA)
    Renderer.DrawRectFilled(Vector2D(bar_x, bar_y), Vector2D(bar_x + bar_w, bar_y + bar_h), accentA, 0)

    -- Time labels: left shows current progress, right shows total duration
    Renderer.DrawText('Verdana', ms_to_mmss(SpotifyInfo.progress_ms or 0), Vector2D(bar_x - 28, bar_y - 7), false, false, Color(0x94, 0x94, 0x94, baseA))
    Renderer.DrawText('Verdana', ms_to_mmss(SpotifyInfo.duration_ms or 0), Vector2D(bar_x + bar_w + 6, bar_y - 7), false, false, Color(0x94, 0x94, 0x94, baseA))

    -- Progress knob (accent, 1D1D1D outline)
    local progress_ratio = 0
    if (SpotifyInfo.duration_ms or 0) > 0 then
      progress_ratio = math.max(0, math.min(1, (SpotifyInfo.progress_ms or 0) / (SpotifyInfo.duration_ms or 1)))
    end
    local knob_x = bar_x + math.floor(progress_ratio * bar_w) - 2
    local knob_w, knob_h = 4, 8
    local knob_y = bar_y - math.floor(knob_h / 2)
    Renderer.DrawRectFilled(Vector2D(knob_x, knob_y), Vector2D(knob_x + knob_w, knob_y + knob_h), accentA, 0)
    Renderer.DrawRect(Vector2D(knob_x, knob_y), Vector2D(knob_x + knob_w, knob_y + knob_h), Color(0x1D, 0x1D, 0x1D, baseA), 0)

    -- Right side: show only time, centered horizontally in the main rect
    local tf_12h = (spotify.timeFormatVar and spotify.timeFormatVar:GetInt() == 1) or false
    local now_str = format_time(os.time(), tf_12h)
    -- Right aligned, vertically centered in main rect, with 5px right padding
    local right_pad = 5
    local time_h = 16
    local time_w = #now_str * 8
    local time_x = main_x + main_w - right_pad - time_w
    local time_y = main_y + math.floor((main_h - time_h) / 2)
    Renderer.DrawText('Verdana', now_str, Vector2D(time_x, time_y), false, false, Color(0x94, 0x94, 0x94, baseA))
  end

  -- Unauthorized re-auth modal using Spotify controls window style
  local has_token = (type(access_token) == 'string' and #access_token > 0)
  if (spotify.testModalVar and spotify.testModalVar:GetBool()) or (has_token and not __sp_setup_mode and __sp_need_reauth and spotify.enabledVar:GetBool()) then
    local screen = Renderer.GetScreenSize()
    local sw, sh = screen.x, screen.y
    -- Dim entire screen
    Renderer.DrawRectFilled(Vector2D(0, 0), Vector2D(sw, sh), Color(0, 0, 0, 120), 0)

    -- Modal dimensions (wider rectangle derived from controls window style)
    local box_w, box_h = 420, 210
    modal_x = modal_x or math.floor((sw - box_w) / 2)
    modal_y = modal_y or math.floor((sh - box_h) / 2)
    local bx, by = modal_x, modal_y

    -- Outer and inner frames
    Renderer.DrawRectFilled(Vector2D(bx, by), Vector2D(bx + box_w, by + box_h), hex_to_color('0E0E0E'), 0)
    local ix, iy = bx + 2, by + 2
    local inner_w, inner_h = box_w - 4, box_h - 4
    Renderer.DrawRectFilled(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('0E0E0E'), 0)
    Renderer.DrawRect(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('1D1D1D'), 0)

    -- Header + accent line (centered label) and drag handle
    local header_h = 24
    Renderer.DrawRectFilled(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + header_h), hex_to_color('151515'), 0)
    Renderer.DrawRectFilled(Vector2D(ix, iy + header_h), Vector2D(ix + inner_w, iy + header_h + 1), hex_to_color('5B86C6'), 0)
    local header_label = 'Spotify token expired'
    local header_text_w = #header_label * 8
    local header_text_x = ix + math.floor((inner_w - header_text_w) / 2)
    local header_text_y = iy + math.floor((header_h - 16) / 2)
    Renderer.DrawText('Verdana', header_label, Vector2D(header_text_x, header_text_y), false, false, Color(255, 255, 255, 255))

    -- Body text
    local body_x = ix + 12
    local body_y = iy + header_h + 14
    local uname = Cheat.GetUserName and (Cheat.GetUserName() or '') or ''
    local line1 = 'Hey, ' .. uname .. ', the token appears to be expired.'
    local line2 = 'Do you want to re-obtain the token now?'
    -- Render body text using white with full alpha for testing visibility
    Renderer.DrawText('Verdana', line1, Vector2D(body_x, body_y), false, false, Color(255, 255, 255, 255))
    Renderer.DrawText('Verdana', line2, Vector2D(body_x, body_y + 18), false, false, Color(255, 255, 255, 255))

    -- Buttons (centered horizontally with even side padding)
    local btn_w, btn_h = 90, 24
    local gap = 12
    local total_btn_w = btn_w * 2 + gap
    local btn_y = iy + inner_h - btn_h - 32 -- move up ~20px
    local start_x = ix + math.floor((inner_w - total_btn_w) / 2)
    local yes_x = start_x
    local no_x  = start_x + btn_w + gap

    local mouse = Input.GetCursorPos()
    local mx, my = mouse.x, mouse.y
    local leftDown = Input.GetKeyDown(1)
    local over_yes = (mx >= yes_x and mx <= yes_x + btn_w and my >= btn_y and my <= btn_y + btn_h)
    local over_no  = (mx >= no_x  and mx <= no_x  + btn_w and my >= btn_y and my <= btn_y + btn_h)
    draw_button('Yes', yes_x, btn_y, btn_w, btn_h, leftDown and over_yes)
    draw_button('No',  no_x,  btn_y, btn_w, btn_h, leftDown and over_no)

    -- Dragging on header
    if leftDown and not __sp_prev_click then
      if mx >= ix and mx <= ix + inner_w and my >= iy and my <= iy + header_h then
        modal_dragging = true
        modal_drag_offx = mx - bx
        modal_drag_offy = my - by
      end
    end
    if modal_dragging then
      if leftDown then
        modal_x = mx - modal_drag_offx
        modal_y = my - modal_drag_offy
      else
        modal_dragging = false
      end
    end

    if leftDown and not __sp_prev_click then
      if over_yes then
        open_url('https://spotify.stbrouwers.cc')
        -- For safety, do NOT programmatically toggle controls menu; just close modal
        __sp_need_reauth = false
        -- Do not reopen unless re-enabled or another 401 occurs
      elseif over_no then
        __sp_need_reauth = false
      end
    end
    __sp_prev_click = leftDown
  end

  -- First-time setup modal (reuses modal styling). Guides through token setup.
  if __sp_setup_mode then
    local screen = Renderer.GetScreenSize()
    local sw, sh = screen.x, screen.y
    Renderer.DrawRectFilled(Vector2D(0, 0), Vector2D(sw, sh), Color(0, 0, 0, 120), 0)

    local box_w, box_h = 420, 230
    modal_x = modal_x or math.floor((sw - box_w) / 2)
    modal_y = modal_y or math.floor((sh - box_h) / 2)
    local bx, by = modal_x, modal_y

    Renderer.DrawRectFilled(Vector2D(bx, by), Vector2D(bx + box_w, by + box_h), hex_to_color('0E0E0E'), 0)
    local ix, iy = bx + 2, by + 2
    local inner_w, inner_h = box_w - 4, box_h - 4
    Renderer.DrawRectFilled(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('0E0E0E'), 0)
    Renderer.DrawRect(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + inner_h), hex_to_color('1D1D1D'), 0)

    -- Header
    local header_h = 24
    Renderer.DrawRectFilled(Vector2D(ix, iy), Vector2D(ix + inner_w, iy + header_h), hex_to_color('151515'), 0)
    Renderer.DrawRectFilled(Vector2D(ix, iy + header_h), Vector2D(ix + inner_w, iy + header_h + 1), hex_to_color('5B86C6'), 0)
    local header_label = (__sp_setup_step == 0 and 'Setup') or (__sp_setup_step == 1 and 'Step 1') or (__sp_setup_step == 2 and 'Step 2') or 'Final step'
    local header_text_w = #header_label * 8
    local header_text_x = ix + math.floor((inner_w - header_text_w) / 2)
    local header_text_y = iy + math.floor((header_h - 16) / 2)
    Renderer.DrawText('Verdana', header_label, Vector2D(header_text_x, header_text_y), false, false, Color(255, 255, 255, 255))

    local body_x = ix + 12
    local body_y = iy + header_h + 14
    local uname = Cheat.GetUserName and (Cheat.GetUserName() or '') or ''
    if __sp_setup_step == 0 then
      Renderer.DrawText('Verdana', 'Hey, ' .. uname .. ', thank you for downloading.', Vector2D(body_x, body_y), false, false, Color(255, 255, 255, 255))
      Renderer.DrawText('Verdana', 'May I guide you through the setup?', Vector2D(body_x, body_y + 18), false, false, Color(255, 255, 255, 255))
    elseif __sp_setup_step == 1 then
      Renderer.DrawText('Verdana', 'Please click Open website to obtain your token.', Vector2D(body_x, body_y), false, false, Color(255, 255, 255, 255))
    elseif __sp_setup_step == 2 then
      Renderer.DrawText('Verdana', 'Great! Now where you copied your access token,', Vector2D(body_x, body_y), false, false, Color(255, 255, 255, 255))
      Renderer.DrawText('Verdana', 'please click Yes to save it.', Vector2D(body_x, body_y + 18), false, false, Color(255, 255, 255, 255))
    else
      Renderer.DrawText('Verdana', "Awesome! You're ready to go. Enjoy!", Vector2D(body_x, body_y), false, false, Color(255, 255, 255, 255))
    end

    -- Buttons
    local btn_w, btn_h = 110, 24
    local gap = 12
    local total_btn_w = btn_w * 2 + gap
    local btn_y = iy + inner_h - btn_h - 24
    local start_x = ix + math.floor((inner_w - total_btn_w) / 2)
    local left_x = start_x
    local right_x = start_x + btn_w + gap
    local mouse = Input.GetCursorPos()
    local mx, my = mouse.x, mouse.y
    local leftDown = Input.GetKeyDown(1)

    local left_label, right_label = 'Yes', 'No'
    if __sp_setup_step == 1 then left_label, right_label = 'Open website', 'Cancel' end
    if __sp_setup_step == 2 then left_label, right_label = 'Yes', 'No' end
    if __sp_setup_step >= 3 then left_label, right_label = 'Finish', 'Cancel' end

    local over_left = (mx >= left_x and mx <= left_x + btn_w and my >= btn_y and my <= btn_y + btn_h)
    local over_right = (mx >= right_x and mx <= right_x + btn_w and my >= btn_y and my <= btn_y + btn_h)
    draw_button(left_label,  left_x,  btn_y, btn_w, btn_h, leftDown and over_left)
    draw_button(right_label, right_x, btn_y, btn_w, btn_h, leftDown and over_right)

    -- Drag header
    if leftDown and not __sp_prev_click then
      if mx >= ix and mx <= ix + inner_w and my >= iy and my <= iy + header_h then
        modal_dragging = true
        modal_drag_offx = mx - bx
        modal_drag_offy = my - by
      end
    end
    if modal_dragging then
      if leftDown then
        modal_x = mx - modal_drag_offx
        modal_y = my - modal_drag_offy
      else
        modal_dragging = false
      end
    end

    if leftDown and not __sp_prev_click then
      if over_left then
        if __sp_setup_step == 0 then
          __sp_setup_step = 1
        elseif __sp_setup_step == 1 then
          open_url('https://spotify.stbrouwers.cc')
          __sp_setup_step = 2
        elseif __sp_setup_step == 2 then
          -- save token from clipboard
          local clip = read_clipboard_text()
          clip = clip and clip:gsub('^%s+', ''):gsub('%s+$', '') or ''
          if #clip > 0 then
            access_token = clip
            save_token()
            __sp_setup_step = 3
          else
            -- keep on step 2; optionally draw warning
          end
        else
          __sp_setup_mode = false
          __sp_suppress_reauth = false
        end
      elseif over_right then
        __sp_setup_mode = false
        __sp_suppress_reauth = false
      end
    end
    __sp_prev_click = leftDown
  end
end

Cheat.RegisterCallback('OnRenderer', OnRenderer);


