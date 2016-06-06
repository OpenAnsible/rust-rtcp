extern crate rand;
use rand::Rng;

// RTCP Packet Format ( https://tools.ietf.org/html/rfc3550#section-6.1 )

// RTCP Control Packet types (PT) : 
//      https://tools.ietf.org/html/rfc3550#section-12.1
//      http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4

// abbrev.  name                 value
// SR       sender report          200
// RR       receiver report        201
// SDES     source description     202
// BYE      goodbye                203
// APP      application-defined    204


// SR: Sender Report RTCP Packet       : https://tools.ietf.org/html/rfc3550#section-6.4.1
// RR: Receiver Report RTCP Packet     : https://tools.ietf.org/html/rfc3550#section-6.4.2
// SDES: Source Description RTCP Packet: https://tools.ietf.org/html/rfc3550#section-6.5
// BYE: Goodbye RTCP Packet            : https://tools.ietf.org/html/rfc3550#section-6.6
// APP: Application-Defined RTCP Packet: https://tools.ietf.org/html/rfc3550#section-6.7



#[derive(Debug)]
pub enum Packet {
    SR(SR),     // Sender Report RTCP Packet
    RR(RR),     // Receiver Report RTCP Packet
    SDES(SDES), // Source Description RTCP Packet
    BYE(BYE),   // Goodbye RTCP Packet
    APP(APP)    // Application-Defined RTCP Packet
}

pub struct SSRC(u32);
impl SSRC {
    pub fn new () -> SSRC {
        let mut rng = rand::thread_rng();
        SSRC(rng.gen::<u32>())
    }
    pub fn from_u32(n: u32) -> SSRC {
        SSRC(n)
    }
    pub fn to_u32(&self) -> u32 {
        self.0
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        let ssrc = format!("{:032b}", self.0);
        bytes.push(u8::from_str_radix(&ssrc[0..8], 2));
        bytes.push(u8::from_str_radix(&ssrc[8..16], 2));
        bytes.push(u8::from_str_radix(&ssrc[16..24], 2));
        bytes.push(u8::from_str_radix(&ssrc[24..32], 2));
        bytes
    }
}

pub struct CSRC(u32);
impl CSRC {
    pub fn new () -> CSRC {
        let mut rng = rand::thread_rng();
        CSRC(rng.gen::<u32>())
    }
    pub fn from_u32(n: u32) -> CSRC {
        CSRC(n)
    }
    pub fn to_u32(&self) -> u32 {
        self.0
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        let csrc = format!("{:032b}", self.0);
        bytes.push(u8::from_str_radix(&csrc[0..8], 2));
        bytes.push(u8::from_str_radix(&csrc[8..16], 2));
        bytes.push(u8::from_str_radix(&csrc[16..24], 2));
        bytes.push(u8::from_str_radix(&csrc[24..32], 2));
        bytes
    }
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=SR=200   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
sender |              NTP timestamp, most significant word             |
info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             NTP timestamp, least significant word             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         RTP timestamp                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     sender's packet count                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      sender's octet count                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#[derive(Debug)]
pub struct SR {
    version: u8,  // 2 bits
    padding: u8,  // 1 bits
    rc     : u8,  // RC/SC, 5 bits
    pt     : u8,  // packet type, 8 bits
    length : u16  // packet length
}
impl SR {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.push(u8::from_str_radix(format!("{:02b}", self.version) 
                + format!("{:01b}", self.padding).as_ref()
                + format!("{:05b}", self.rc).as_ref(), 2).unwrap());

        bytes.push(self.pt);
        let length = format!("{:016b}", self.length);
        bytes.push(u8::from_str_radix(&length[0..8], 2));
        bytes.push(u8::from_str_radix(&length[8..16], 2));
        bytes
    }
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=RR=201   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     SSRC of packet sender                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


*/
#[derive(Debug)]
pub struct RR {
    version: u8,
    padding: u8,
    sc     : u8,  // RC/SC
    pt     : u8,  // packet type
    length : u16  // packet length
}


/*

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    SC   |  PT=SDES=202  |             length            |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_1                          |
  1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_2                          |
  2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

RTP SDES item types:
    https://tools.ietf.org/html/rfc3550#section-12.2
    http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-5
    
    abbrev.  name                            value
    END      end of SDES list                    0
    CNAME    canonical name                      1
    NAME     user name                           2
    EMAIL    user's electronic mail address      3
    PHONE    user's phone number                 4
    LOC      geographic user location            5
    TOOL     name of application or tool         6
    NOTE     notice about the source             7
    PRIV     private extensions                  8

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    CNAME=1    |     length    | user and domain name        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#[derive(Debug)]
pub struct SDES {
    version: u8,
    padding: u8,
    sc     : u8,  // RC/SC
    pt     : u8,  // packet type
    length : u16  // packet length
    ssrc   : SSRC,
    items  : Vec<SDES_ITEM>
}


#[derive(Debug)]
pub enum SDES_ITEM {
    // http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-5
    END  { value: u8, length: u8, content: String },      // 0
    CNAME{ value: u8, length: u8, content: String },      // 1
    NAME { value: u8, length: u8, content: String },      // 2
    EMAIL{ value: u8, length: u8, content: String },      // 3
    PHONE{ value: u8, length: u8, content: String },      // 4
    LOC  { value: u8, length: u8, content: String },      // 5
    TOOL { value: u8, length: u8, content: String },      // 6
    NOTE { value: u8, length: u8, content: String },      // 7
    PRIV { value: u8, length: u8, content: String },      // 8
    H323_CADDR { value: u8, length: u8, content: String },// 9
    APSI       { value: u8, length: u8, content: String },// 10
    RGRP       { value: u8, length: u8, content: String },// 11
    UNASSIGNED { value: u8, length: u8, content: String },// 12 - 255, Unassigned
}


impl SDES_ITEM {
    pub fn to_u8 (&self) -> u8 {
        match *self {
            SDES_ITEM::END(ref item)   => *item.value,
            SDES_ITEM::CNAME(ref item) => *item.value,
            SDES_ITEM::NAME(ref item)  => *item.value,
            SDES_ITEM::EMAIL(ref item) => *item.value,
            SDES_ITEM::PHONE(ref item) => *item.value,
            SDES_ITEM::LOC(ref item)   => *item.value,
            SDES_ITEM::TOOL(ref item) => *item.value,
            SDES_ITEM::NOTE(ref item) => *item.value,
            SDES_ITEM::PRIV(ref item) => *item.value,
            SDES_ITEM::H323_CADDR(ref item) => *item.value,
            SDES_ITEM::APSI(ref item) => *item.value,
            SDES_ITEM::RGRP(ref item) => *item.value,
            SDES_ITEM::UNASSIGNED(ref item) => *item.value
        }
    }
    pub fn from_u8(n: u8) -> Result<SDES_ITEM, &'static str> {
        match n {
            0  => Ok(SDES_ITEM::END),
            1  => Ok(SDES_ITEM::CNAME),
            2  => Ok(SDES_ITEM::NAME),
            3  => Ok(SDES_ITEM::EMAIL),
            4  => Ok(SDES_ITEM::PHONE),
            5  => Ok(SDES_ITEM::LOC),
            6  => Ok(SDES_ITEM::TOOL),
            7  => Ok(SDES_ITEM::NOTE),
            8  => Ok(SDES_ITEM::PRIV),
            9  => Ok(SDES_ITEM::H323_CADDR),
            10 => Ok(SDES_ITEM::APSI),
            11 => Ok(SDES_ITEM::RGRP),
            12 ... 255 => Ok(SDES_ITEM::UNASSIGNED),
            _  => Err("_")
        }
    }
}

#[derive(Debug)]
pub struct BYE {
    version: u8,
    padding: u8,
    sc     : u8,  // RC/SC
    pt     : u8,  // packet type
    length : u16, // packet length
    ssrc   : Vec<SSRC>
}
impl BYE {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.push(u8::from_str_radix(format!("{:02b}", self.version) 
                + format!("{:01b}", self.padding).as_ref()
                + format!("{:05b}", self.sc).as_ref(), 2).unwrap());

        bytes.push(self.pt);
        let length = format!("{:016b}", self.length);
        bytes.push(u8::from_str_radix(&length[0..8], 2));
        bytes.push(u8::from_str_radix(&length[8..16], 2));
        for ssrc in self.ssrc.iter() {
            bytes.extend(ssrc.to_bytes());
        }
        bytes
    }
}

#[derive(Debug)]
pub struct APP {
    version: u8,
    padding: u8,
    subtype: u8,  // 5 bits
    pt     : u8,  // packet type
    length : u16, // packet length
    ssrc   : SSRC,
    name   : String, // 32 bits
    // ext    : u32    // 32 bits, extension data length
    ext_len: u32,
    ext    : Vec<u8>  // extension data.
}
impl APP {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.push(u8::from_str_radix(format!("{:02b}", self.version) 
                + format!("{:01b}", self.padding).as_ref()
                + format!("{:05b}", self.subtype).as_ref(), 2).unwrap());

        bytes.push(self.pt);
        let length = format!("{:016b}", self.length);
        bytes.push(u8::from_str_radix(&length[0..8], 2));
        bytes.push(u8::from_str_radix(&length[8..16], 2));
        bytes.extend(self.ssrc.to_bytes());
        bytes.extend(self.name.as_bytes());
        let ext_length = format!("{:032b}", self.ext_len);
        bytes.push(u8::from_str_radix(&ext_length[0..8], 2));
        bytes.push(u8::from_str_radix(&ext_length[8..16], 2));
        bytes.push(u8::from_str_radix(&ext_length[16..24], 2));
        bytes.push(u8::from_str_radix(&ext_length[24..32], 2));
        bytes.extend(self.ext);
        bytes
    }
}
