use std::net::{SocketAddr, UdpSocket};

const DNS_SERVER: &'static str = "192.168.1.254:53";

#[derive(Debug)]
enum Error{
    DnsLabelTooLong,
    DnsNameTooLong,
    OnlyOneQuestionSupported,
}

type Result<T> = std::result::Result<T, self::Error>;

fn main() {

    let socket = UdpSocket::bind("0.0.0.0:53").unwrap();
    let forward_dns_server: SocketAddr = DNS_SERVER.parse().unwrap();
    let forward_socket = UdpSocket::bind("0.0.0.0:5335").unwrap();
    forward_socket.connect(forward_dns_server).unwrap();

    loop {

        // Wait for a UDP Packet
        let mut recv_buf = [0u8; 512];
        let src_addr = match socket.recv_from(&mut recv_buf){
            Ok((_, src_addr)) => src_addr,
            _ => {
                continue
            }
        };
        // Try to parse
        let mut request = match Dns::parse(&recv_buf){
            Ok(request) => request,
            Err(err) => {
                println!("{err:?}");
                continue;
            }
        };
    
        // We dont know about it, forward it to next resolver
        let mut recv_buf = [0u8; 512];
        let mut send_buf = [0u8; 512];
        let forward_request = Dns::request(request.query);
        let len = forward_request.serialise(&mut send_buf).unwrap();
        forward_socket.send(&send_buf[..len]).unwrap();
        forward_socket.recv(&mut recv_buf).unwrap();
        // Try to parse response from forward DNS server
        let forward_response = match Dns::parse(&recv_buf){
            Ok(request) => request,
            Err(err) => {
                println!("{err:?}");
                continue;
            }
        };
        println!("{forward_response:?}");
        // Respond to client
        let mut send_buf = [0u8; 512];
        request.respond(&forward_response);
        let len = request.serialise(&mut send_buf).unwrap();
        socket.send_to(&send_buf[..len], src_addr).unwrap();
    }
}

/// Struct for storing the data from a DNS query inside a [Dns]
#[derive(Debug, Clone, Copy)]
struct Query{
    domain_name: [u8; 253],
    domain_name_len: usize,
    ty: u16,
    class: u16,
}

/// Struct for storing the data from a DNS query inside a [Dns]
#[derive(Debug, Clone, Copy)]
struct Answer{
    name: [u8; 2],
    ty: u16,
    class: u16,
    ttl: u32,
    len: u16,
    address: [u8; 4],
}


/// Struct for storing the data from a DNS Request
#[derive(Debug)]
struct Dns {
    transaction_id: [u8; 2],
    flags: u16,
    questions: u16,
    answer_records: u16,
    authority_records: u16,
    additional_records: u16,
    query: Query,
    answer: Option<Answer>
}

impl Dns {

    const DNS_FLAG_RESPONSE: u16 = (1 << 15) as u16;
    
    fn parse(payload: &[u8; 512]) -> Result<Self> {
        let transaction_id: [u8; 2] = [payload[0], payload[1]];
        let flags: u16 = (payload[2] as u16) << 8 | payload[3] as u16;
        let questions: u16 = (payload[4] as u16) << 8 | payload[5] as u16;

        if questions > 1 {
            return Err(Error::OnlyOneQuestionSupported);
        }

        let answer_records: u16 = (payload[6] as u16) << 8 | payload[7] as u16;
        let authority_records: u16 = (payload[8] as u16) << 8 | payload[9] as u16;
        let additional_records: u16 = (payload[10] as u16) << 8 | payload[11] as u16;

        // Parse Query
        let domain_name_start = 12;
        let mut domain_name = [0u8; 253];
        let mut domain_name_pointer = 0;
        loop {
            let label_len: usize = payload[
                domain_name_start + domain_name_pointer
            ] as usize;

            // Labels cannot exceed 63 characters
            if label_len > 63 {
                return Err(Error::DnsLabelTooLong);
            }

            domain_name_pointer += label_len + 1;

            // DNS name max size is 253
            if domain_name_pointer > 253{
                return Err(Error::DnsNameTooLong);
            }

            // No more labels
            if label_len == 0x00 {
                domain_name[..domain_name_pointer].copy_from_slice(
                    &payload[
                        domain_name_start ..
                        domain_name_start + domain_name_pointer
                    ]
                );
                break;
            }
        }
        let domain_name_end = domain_name_start + domain_name_pointer;
        let query_ty =  
            (payload[domain_name_end] as u16) << 8 | 
            payload[domain_name_end + 1] as u16;
        let query_class = 
            (payload[domain_name_end + 2] as u16) << 8 | 
            payload[domain_name_end + 3] as u16;
        let query_end = domain_name_end + 4;
        // Parse answer
        let answer = if answer_records > 0 {
            let name: [u8; 2] = [
                payload[query_end + 0],
                payload[query_end + 1],
            ];
            let ty: [u8; 2] = [
                payload[query_end + 2],
                payload[query_end + 3],
            ];
            let class: [u8; 2] = [
                payload[query_end + 4],
                payload[query_end + 5],
            ];
            let ttl: [u8; 4] = [
                payload[query_end + 6],
                payload[query_end + 7],
                payload[query_end + 8],
                payload[query_end + 9],
            ];
            let len: [u8; 2] = [
                payload[query_end + 10],
                payload[query_end + 11],
            ];
            let address: [u8; 4] = [
                payload[query_end + 12],
                payload[query_end + 13],
                payload[query_end + 14],
                payload[query_end + 15],
            ];
            Some(Answer{
                name,
                ty: u16::from_be_bytes(ty),
                class: u16::from_be_bytes(class),
                ttl: u32::from_be_bytes(ttl),
                len: u16::from_be_bytes(len),
                address,
            })
        }else{
            None
        };

        Ok(Self { 
            transaction_id,
            flags,
            questions,
            answer_records,
            authority_records,
            additional_records,
            query: Query{
                domain_name,
                domain_name_len: domain_name_pointer,
                ty: query_ty,
                class: query_class,
            },
            answer,
        })
    }
    
    /// Craft a [Dns] request
    fn request(query: Query) -> Self {

        Self { 
            transaction_id: [0x13, 0x37], 
            flags: 0x100, 
            questions: 1, 
            answer_records: 0, 
            authority_records: 0, 
            additional_records: 0, 
            query,
            answer: None,
        }

    }

    fn respond(&mut self, response_from_forward_dns: &Self) {
        self.flags = Self::DNS_FLAG_RESPONSE;
        self.answer_records = 1;
        self.authority_records = 0;
        self.additional_records = 0;
        self.answer = response_from_forward_dns.answer;
    }

    /// Takes a [u8; 512] buffer and writes the response based on the requests
    fn serialise(self, buf: &mut [u8; 512]) -> Result<usize> {

        let mut buf_ptr = 0;

        // This is the data to be added to our send buffer using a helper
        // function that keeps track of lengths
        let fields = [
            &self.transaction_id,
            &self.flags.to_be_bytes(),
            &self.questions.to_be_bytes(),
            &self.answer_records.to_be_bytes(),
            &self.authority_records.to_be_bytes(),
            &self.additional_records.to_be_bytes(),
            &self.query.domain_name[..self.query.domain_name_len],
            &self.query.ty.to_be_bytes(),
            &self.query.class.to_be_bytes(),
        ];
        
        for field in fields {
            Self::append_to_buffer(buf, &mut buf_ptr, field);
        }
        
        // If we are responding as resolver
        if let Some(answer) = self.answer{
            let fields: [&[u8]; 6] = [
                &answer.name,
                &answer.ty.to_be_bytes(),
                &answer.class.to_be_bytes(),
                &answer.ttl.to_be_bytes(),
                &answer.len.to_be_bytes(),
                &answer.address,
            ];
            for field in fields {
                Self::append_to_buffer(buf, &mut buf_ptr, field);
            }
        } 

        Ok(buf_ptr)
    }

    fn append_to_buffer(buf: &mut [u8; 512], buf_ptr: &mut usize, bytes: &[u8]){
        let bytes_len = bytes.len();
        buf[*buf_ptr .. *buf_ptr + bytes_len].copy_from_slice(&bytes);
        *buf_ptr += bytes_len;
    }
}

