#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "fileutils"
require "json"

requests_path = File.expand_path(
  ARGV.fetch(0, "../../../compat/regex-corpus/requests-v1.jsonl"),
  __dir__
)
output_dir = File.expand_path(ARGV.fetch(1, "corpus/go_regex"), __dir__)
FileUtils.mkdir_p(output_dir)

count = 0
File.foreach(requests_path) do |line|
  request = JSON.parse(line)
  pattern = Base64.strict_decode64(request.fetch("pattern_base64"))
  haystack = Base64.strict_decode64(request.fetch("input_base64"))
  abort "pattern exceeds the u16 seed-frame limit: #{request.fetch("id")}" if pattern.bytesize > 0xffff

  safe_id = request.fetch("id").gsub(/[^A-Za-z0-9_.-]+/, "_")
  seed_path = File.join(output_dir, format("%04d-%s", count + 1, safe_id))
  File.binwrite(seed_path, [pattern.bytesize].pack("v") + pattern + haystack)
  count += 1
end

puts "wrote #{count} GoRegex seeds to #{output_dir}"
