---@diagnostic disable: need-check-nil
function descriptor()
  return {
    title = "VLC Subsonic client",
    version = "1.0",
    author = "jrosh",
    shortdesc = "VLC Subsonic client",
    description = "Play music from your subsonic server with VLC as client",
  }
end

function activate()
  if (read_config_file()) then
    open_playlists_dialog()
  else
    open_login_dialog()
  end
end

function deactivate()
  dlg:delete()
end

function open_login_dialog()
  dlg = vlc.dialog(descriptor().title)
  dlg:add_label("<center><h3>Enter your server details</h3></center>", 1,1,1,1)
  local host_w = dlg:add_text_input("", 1,2,1,1)
  local user_w = dlg:add_text_input("", 1,3,1,1)
  local pass_w = dlg:add_text_input("", 1,4,1,1)
  local status_label = dlg:add_label("", 1,7,1,1)

  local test_button dlg:add_button("Test connection", function()
    local host = host_w:get_text()
    local user = user_w:get_text()
    local pass = pass_w:get_text()
    status_label:set_text("")
    local result = test_connection(host, user, pass)
    status_label:set_text(result)
  end, 1,5,1,1)

  local save_button dlg:add_button("Save config and login", function()
    local host = host_w:get_text()
    local user = user_w:get_text()
    local pass = pass_w:get_text()
    --local encryption_key = generateRandomAESKey()
    --local encrypted_pass = encrypt_password(pass, encryption_key)
    --write_config_file(host, user, encrypted_pass, encryption_key)
    write_config_file(host, user, pass)
    status_label:set_text("")
    status_label:set_text("Config saved, please reload the extension")
    dlg:del_widget(host_w, user_w, pass_w, test_button, save_button)
    open_playlists_dialog()
  end, 1,6,1,1)
  dlg:show()
end

function test_connection(hostname, username, password)
  local url_s = generate_salt(6)
  local url_t = calculate_md5(password .. url_s)
  local url = hostname.."/rest/ping?&u="..username.."&t="..url_t.."&s="..url_s.."&v=1.16.1&c=vlc"
  local stream = vlc.stream(url)
  if not stream then
      vlc.msg.err("Failed to open stream for URL: " .. url)
      return nil
  end
  local chunk_data = ""
  local testing_chunk = stream:read(1024) 
  if testing_chunk then
    chunk_data = (chunk_data .. testing_chunk:gsub("\n", ""))
  else
      vlc.msg.err("Failed to read data from stream")
  end
  local response = chunk_data:match('status="([^"]+)"')
  return response
end

function open_playlists_dialog()
  if not dlg then
    dlg = vlc.dialog(descriptor().title)
  end
  config = read_config_file() -- keep global at this position
  --password = decrypt_password(config['password'], os.getenv("VLC_SUBSONIC_EXTENSION"))
  local url_s = generate_salt(6)
  local url_t = calculate_md5(config["password"] .. url_s)
  --local url = string.format("%s/rest/getPlaylists?&u=%s&t=%s&s=%s&v=1.16.1&c=vlc", config['hostname'], config['username'], url_t, url_s )
  local url =  config['hostname'] .. "/rest/getPlaylists?&u=" .. config['username'] .. "&t=" .. url_t .. "&s="..url_s.."&v=1.16.1&c=vlc"
  local playlist_table = fetch_xml_data(url)
  local playlists = {}
  local names = {}
  local ids = {}

  -- occurrences of name="value" and 'playlist id="value"'
  playlist_table:gsub('name="([^"]*)"', function(name)
      table.insert(names, name)
  end)
  playlist_table:gsub('playlist%s+id="([^"]*)"', function(playlist_id)
      table.insert(ids, playlist_id)
  end)

  -- combining names and ids into the playlists table
  for i = 1, math.max(#names, #ids) do
      local name = names[i] or "Unnamed"
      local playlist_id = ids[i] or "No ID"
      table.insert(playlists, {name = name, playlist_id = playlist_id})
  end
  -- display playlists in the grid
  local col = 0
  local row = 0
  for index, playlist in ipairs(playlists) do
    row = ( index % 10 ) + 2
    col = math.ceil(index / 10)
    dlg:add_button(playlist.name, function() add_to_local_playlist(playlist.playlist_id) end, col, row)
  end
  dlg:add_label("<center><h3>Playlists</h3></center>", 1,1, col)
  dlg:show()
end

function add_to_local_playlist(playlist_id)
  local url_s = generate_salt(6)
  local url_t = calculate_md5(config['password'] .. url_s)
  local playlist_url = config['hostname'] .. "/rest/getPlaylist?id="..playlist_id.."&u=".. config['username'] .."&t="..url_t.."&s="..url_s.."&v=1.16.1&c=vlc"

  local songs_table = fetch_xml_data(playlist_url)

  vlc.playlist.clear()

  for song in string.gmatch(songs_table, "<entry.-</entry>") do
    local id = string.match(song, 'id="([^"]-)"')
    local title = string.match(song, 'title="([^"]-)"')
    local url_s = generate_salt(6)
    local url_t = calculate_md5(config['password'] .. url_s)
    local song_url = config['hostname'] .. "/rest/stream?id=".. id .."&u=".. config['username'] .."&t="..url_t.."&s="..url_s.."&v=1.16.1&c=vlc"
    vlc.playlist.add({{path=song_url, title=title}})
  end
  --vlc.playlist.goto(0) <- doesn't launch the extension. goto() was added as an internal lua function from 5.2 but VLC sould use 5.1. idk whats going on
end

function fetch_xml_data(url)
  local stream = vlc.stream(url)
  if not stream then
      vlc.msg.err("Failed to open stream for URL: " .. url)
      return nil
  end
  local xml_data = ""
  -- Read a initial chunk of data to see if we get a response
  local initial_chunk = stream:read(1024)  -- Read the first 1024 bytes
  if initial_chunk then
    xml_data = (xml_data .. initial_chunk:gsub("\n", ""))  -- Append the initial chunk
  else
      vlc.msg.err("Failed to read data from stream")
  end
  -- Continue reading until EOF
  while true do
      local chunk = stream:read(1024)  -- Read more data in chunks
      if not chunk or chunk == "" then
          break
      end
      xml_data = (xml_data .. chunk:gsub("\n", ""))  -- Append each chunk to the complete data
  end
  return xml_data
end

function calculate_md5(str)
  local command = string.format("echo -n %s | openssl dgst -md5", str)
  local handle = io.popen(command)
  local md5hash = handle:read("*a")
  handle:close()
  return md5hash:match("= (%x+)")
end

function generate_salt(length)
  local salt = ""
  for i = 1, length do
      local char = string.char(math.random() < 0.33 and math.random(48, 57) or math.random() < 0.66 and math.random(65, 90) or math.random(97, 122))
      salt = salt .. char
  end
  return salt
end

function file_exists(filename)
  local file = io.open(filename, "rb")
  if file then
    file:close()
  end
  return file ~= nil
end

function read_config_file()
  local config_file = vlc.config.configdir() .. "/vlc_subsonic.conf"
  local config = {}
  local file = io.open(config_file, "r")
  if not file then
      return nil
  end

  for line in file:lines() do
      local key, value = line:match("([^=]+)=([^=]*)")
      if key and value then
        key = key:match("^%s*(.-)%s*$")
        value = value:match("^%s*(.-)%s*$")
        config[key] = value
      end
  end
  file:close()
  return config
end

function write_config_file(hostname, username, password)
  local config_file = vlc.config.configdir() .. "/vlc_subsonic.conf"
  local file, err = io.open(config_file, "w")
  if file then
      io.output(file)
      io.write("hostname=" .. hostname .. "\n")
      io.write("username=" .. username .. "\n")
      io.write("password=" .. password)
      file:close()
  else
      vlc.msg.err("Error: Could not open file for writing. " .. err)
  end
end

-- not in use from here
function encrypt_password(password, key)
  print(password .. " -> " .. key)
  local command = string.format("echo -n '%s' | openssl enc -base64 -aes-256-cbc -e -pass pass:%s -pbkdf2", password, key)
  local handle = io.popen(command)
  local encryptedPassword = handle:read("*a")
  handle:close()
  return encryptedPassword:gsub("%s+", "")
end

function decrypt_password(encryptedPassword, key)
  print(encryptedPassword .. " -> " .. key)
  local command = string.format("echo '%s' | openssl enc -base64 -aes-256-cbc -d -pass pass:%s -pbkdf2", encryptedPassword, key)
  local handle = io.popen(command)
  local decryptedPassword = handle:read("*a")
  handle:close()
  return decryptedPassword:gsub("%s+", "")
end

function generateRandomAESKey()
  local key = {}
  math.randomseed(os.time())
  for i = 1, 16 do
      local byte = math.random(0, 255)
      table.insert(key, string.char(byte))
  end
  return table.concat(key)
end

function set_or_update_env_var(var_value) --doesnt work (writes new key each time)
  local homerc = vlc.config.homedir() .. "/.bashrc"
  local file = io.open(homerc, "r")
  local rccontent = file:read("*a")
  file:close()
  local new_env_var = string.format("export VLC_SUBSONIC_EXTENSION=\"%s\"", var_value)
  if rccontent:find("^export VLC_SUBSONIC_EXTENSION=") then
      rccontent = rccontent:gsub("export VLC_SUBSONIC_EXTENSION=\"[^\"]*\"", new_env_var)
  else
      rccontent = rccontent .. "\n" .. new_env_var
  end
  local file = io.open(homerc, "w")
  file:write(rccontent)
  file:close()
end
