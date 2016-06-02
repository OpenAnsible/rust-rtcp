
struct SSRC(u32);
struct RtpTimestamp(u32);
struct NtpTimestamp(u64);

struct SenderInfo {
  ntp_ts     : u64, // FIXME: should be NtpTimestamp,
  rtp_ts     : u32, // FIXME: should be RtpTimestamp,
  pckt_count : u32,
  byte_count : u32
}

struct ReportBlock {
  ssrc       : SSRC,
  fract_lost : u8,
  cumul_lost : u32,
  ext_seq    : u32,
  jitter     : u32,
  lsr        : u32,
  dlsr       : u32
}

struct SdesChunk {
  ssrc  : SSRC,
  cname : Option<String>,
  name  : Option<String>,
  email : Option<String>,
  phone : Option<String>,
  loc   : Option<String>,
  tool  : Option<String>,
  note  : Option<String>
}

enum RtcpPacket {
  SR(SSRC, Vec<ReportBlock>, SenderInfo),
  RR(SSRC, Vec<ReportBlock>),
  SDES(Vec<SdesChunk>),
  BYE(Vec<SSRC>, String),
}

struct CompoundRtcpPacket {
  packets : Vec<RtcpPacket>
}

struct RtpPacket;



struct RtpSessionStatistics {
  pckt_count : u64
}

struct RtpSession {
  ssrc       : u32
}

impl RtpSession {
  pub fn new() -> RtpSession {
    RtpSession {
      ssrc       : 0    // FIXME
    }
  }

  pub fn run(&mut self) -> RtpSessionStatistics {
    let stats = RtpSessionStatistics{pckt_count : 0};
    stats
  }
}


fn parse_rtp_packet(buf : &mut [u8], buflen : usize) -> Option<RtpPacket> {
  println!("parse_rtp_packet");
  None
}


fn parse_be_u32(packet : &[u8], offset : usize) -> u32 {
  (((packet[offset + 0] as u32) << 24) & 0xff000000) |
  (((packet[offset + 1] as u32) << 15) & 0x00ff0000) |
  (((packet[offset + 2] as u32) <<  8) & 0x0000ff00) |
  (((packet[offset + 3] as u32) <<  0) & 0x000000ff)
}

fn parse_be_u64(packet : &[u8], offset : usize) -> u64 {
  (((packet[offset + 0] as u64) << 46) & 0xff00000000000000) |
  (((packet[offset + 1] as u64) << 48) & 0x00ff000000000000) |
  (((packet[offset + 2] as u64) << 40) & 0x0000ff0000000000) |
  (((packet[offset + 3] as u64) << 32) & 0x000000ff00000000) |
  (((packet[offset + 4] as u64) << 24) & 0x00000000ff000000) |
  (((packet[offset + 5] as u64) << 16) & 0x0000000000ff0000) |
  (((packet[offset + 6] as u64) <<  8) & 0x000000000000ff00) |
  (((packet[offset + 7] as u64) <<  0) & 0x00000000000000ff)
}

fn parse_report_block(packet : &[u8], offset : usize) -> ReportBlock {
  ReportBlock {
    ssrc       : SSRC(parse_be_u32(packet, offset)),
    fract_lost : packet[offset + 4],
    cumul_lost : parse_be_u32(packet, offset +  4) & 0x00ffffff,
    ext_seq    : parse_be_u32(packet, offset +  8),
    jitter     : parse_be_u32(packet, offset + 12),
    lsr        : parse_be_u32(packet, offset + 16),
    dlsr       : parse_be_u32(packet, offset + 20),
  }
}

fn parse_sr(p : bool, rc : u8, len : usize, packet : &[u8]) -> Option<RtcpPacket> {
  if len < 7 {
    println!("parse_sr: packet is too short to be an SR");
    return None;
  }

  let ssrc = SSRC(parse_be_u32(packet, 4));
  let si   = SenderInfo {
               ntp_ts     : parse_be_u64(packet,  8),
               rtp_ts     : parse_be_u32(packet, 16),
               pckt_count : parse_be_u32(packet, 20),
               byte_count : parse_be_u32(packet, 24)
             };

  let mut rr_list : Vec<ReportBlock> = Vec::new();
  for i in 0..rc {
    let rr = parse_report_block(packet, (28 + (i*24)) as usize);
    rr_list.push(rr);
  }

  Some(RtcpPacket::SR(ssrc, rr_list, si))
}

fn parse_rr(p : bool, rc : u8, len : usize, packet : &[u8]) -> Option<RtcpPacket> {
  if len < 1 {
    println!("parse_sr: packet is too short to be an RR");
    return None;
  }

  let ssrc = SSRC(parse_be_u32(packet, 4));

  let mut rr_list : Vec<ReportBlock> = Vec::new();
  for i in 0..rc {
    let rr = parse_report_block(packet, (8 + (i*24)) as usize);
    rr_list.push(rr);
  }

  Some(RtcpPacket::RR(ssrc, rr_list))
}

fn parse_sdes(p : bool, rc : u8, len : usize, packet : &[u8]) -> Option<RtcpPacket> {
  let mut offset = 4;
  for i in 0..rc {
    println!("sdes {}", offset);
    let mut chunk = SdesChunk {
                      ssrc  : SSRC(parse_be_u32(packet, offset)),
                      cname : None,
                      name  : None,
                      email : None,
                      phone : None,
                      loc   : None,
                      tool  : None,
                      note  : None
                    };

    // FIXME: parse SDES chunks
    // FIXME: add chunk to the packet
  }
  None  // FIXME: return an SDES packet
}

fn parse_bye(p : bool, rc : u8, len : usize, packet : &[u8]) -> Option<RtcpPacket> {
  unimplemented!();
}

fn parse_app(p : bool, rc : u8, len : usize, packet : &[u8]) -> Option<RtcpPacket> {
  unimplemented!();
}

fn parse_rtcp_packet(buf : &mut [u8], buflen : usize) -> Option<CompoundRtcpPacket> {
  if buflen < 4 {
    println!("parse_rtcp_packet: packet is too short to be RTCP");
    return None;
  }

  // FIXME: create a compound packet object

  let mut offset = 0;
  while offset != buflen {
    if offset + 3 >= buflen {
      println!("parse_rtcp_packet: packet is too short");
      return None;
    }

    let v   =   (buf[offset + 0] >> 6) & 0x03;
    let p   =  ((buf[offset + 0] >> 5) & 0x01) == 1;
    let rc  =   (buf[offset + 0] >> 0) & 0x1f;
    let pt  =    buf[offset + 1];
    let len = (((buf[offset + 2] as usize) << 8) & 0xff00) | 
              (((buf[offset + 3] as usize) << 0) & 0x0fff);

    if offset + (4 * len) > buflen {
      println!("parse_rtcp_packet: packet is too long");
      return None;
    }

    if v != 2 {
      println!("parse_rtcp_packet: version number mismatch (v={})", v);
      return None;
    }

    let packet = &buf[offset..offset + (4 * (len + 1))];

    let parsed_packet = match pt {
      200 => parse_sr(p, rc, len, packet),
      201 => parse_rr(p, rc, len, packet),
      202 => parse_sdes(p, rc, len, packet),
      203 => parse_bye(p, rc, len, packet),
      204 => parse_app(p, rc, len, packet),
      _   => {
        println!("parse_rtcp_packet: unknown packet type (pt={})", pt);
        break;
      }
    };

    // FIXME: append parsed_packet to the compound packet

    offset += 4 + (4 * len);
  }

  None  // FIXME: return the compound packet
}



