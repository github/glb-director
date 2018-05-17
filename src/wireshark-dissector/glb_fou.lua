do
  local ip = Dissector.get("ip")
  local ipv6 = Dissector.get("ipv6")

  -- legacy GLB header based on GRE

  local glbgre = Proto("glbgre","GLB GRE")
  local flags  = ProtoField.new   ("Flags", "glbgre.flags", ftypes.UINT16)
  local proto  = ProtoField.new   ("Protocol Type", "glbgre.protocol_type", ftypes.UINT16)
  local alt    = ProtoField.new   ("Alternate Server", "glbgre.alternate_server", ftypes.IPv4)
  glbgre.fields = { flags, proto, alt }

  function glbgre.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("GLB GRE")

    local pktlen = tvbuf:reported_length_remaining()

    local tree = root:add(glbgre, tvbuf(0,8))
    tree:add(flags, tvbuf(0,2))
    tree:add(proto, tvbuf(2,2))
    tree:add(alt,   tvbuf(4,4))

    ip:call(tvbuf(8):tvb(), pktinfo, root)
  end

  -- GLB Chained Routing, part of the GUE private data

  local glbguerouting = Proto("glbguerouting", "GLB GUE Chained Routing")
  local private_type= ProtoField.new   ("Private Data Type", "glbguerouting.private_type", ftypes.UINT16)
  local next_hop    = ProtoField.new   ("Next Hop", "glbguerouting.next_hop", ftypes.UINT8)
  local hop_count   = ProtoField.new   ("Hop Count", "glbguerouting.hop_count", ftypes.UINT8)
  local hop         = ProtoField.new   ("Hop", "glbguerouting.hop", ftypes.IPv4)
  glbguerouting.fields = { private_type, next_hop, hop_count, hop }

  local hop_count_field  = Field.new("glbguerouting.hop_count")

  function glbguerouting.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("GLB GUE Chained Routing")

    local pktlen = tvbuf:reported_length_remaining()

    local tree = root:add(glbguerouting, tvbuf(0,4))
    tree:add(private_type,     tvbuf(0,2))
    tree:add(next_hop,  tvbuf(2,1))
    tree:add(hop_count, tvbuf(3,1))

    local hop_count_val = hop_count_field()()
    local hops = tree:add("Hops")
    for i = 0,hop_count_val - 1
    do
      hops:add(hop, tvbuf(4 + (i*4),4))
    end

    return 4 + (hop_count_val * 4)
  end

  -- GLB over GUE with GLB-based private data (defined above).

  local glbguerouting_d = Dissector.get("glbguerouting")

  local glbgue = Proto("glbgue","GLB GUE")
  local guevcl      = ProtoField.new   ("GUE Header", "glbgue.vcl", ftypes.UINT8, nil, base.HEX)
  local version     = ProtoField.new   ("Version", "glbgue.vcl.version", ftypes.UINT8, nil, base.DEC, 0xC0)
  local control_msg = ProtoField.new   ("Control Msg", "glbgue.vcl.control_msg", ftypes.UINT8, nil, base.DEC, 0x20)
  local hlen        = ProtoField.new   ("Header Len", "glbgue.vcl.hlen", ftypes.UINT8, nil, base.DEC, 0x1F)
  local proto       = ProtoField.new   ("Protocol Type", "glbgue.protocol_type", ftypes.UINT8)
  local flags       = ProtoField.new   ("Flags", "glbgue.flags", ftypes.UINT16)
  -- local alt         = ProtoField.new   ("Alternate Server", "glbgue.alternate_server", ftypes.IPv4)
  glbgue.fields = { guevcl, version, control_msg, hlen, proto, flags }

  local hlen_field  = Field.new("glbgue.vcl.hlen")
  local proto_field  = Field.new("glbgue.protocol_type")

  function glbgue.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("GLB GUE")

    local pktlen = tvbuf:reported_length_remaining()

    local tree = root:add(glbgue, tvbuf(0,4))
    tree:add(guevcl,      tvbuf(0,1))
    tree:add(version,     tvbuf(0,1))
    tree:add(control_msg, tvbuf(0,1))
    tree:add(hlen,        tvbuf(0,1))
    tree:add(proto,       tvbuf(1,1))
    tree:add(flags,       tvbuf(2,2))

    local hlen_val = hlen_field()()

    local private_len = hlen_val
    if private_len > 0 then
      glbguerouting_d:call(tvbuf(4):tvb(), pktinfo, tree)
    end

    if proto_field()() == 41 then
      ipv6:call(tvbuf((1 + hlen_val) * 4):tvb(), pktinfo, root)
    else
      ip:call(tvbuf((1 + hlen_val) * 4):tvb(), pktinfo, root)
    end
  end

  local udp_port_table = DissectorTable.get("udp.port")
  udp_port_table:add(19522, glbgre)
  udp_port_table:add(19523, glbgue)
end
