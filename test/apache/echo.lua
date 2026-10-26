function handle(r)
  r.content_type = "text/plain"
  local body = ""
  if r.method == "POST" or r.method == "PUT" then
    body = r:requestbody() or ""
  end
  r:puts(string.format("%s %d\n", r.method, #body))
  return apache2.OK
end
