use std::net::UdpSocket;

#[derive(Debug)]
enum Error{
    DnsLabelTooLong,
    DnsNameTooLong,
    OnlyOneQuestionSupported,
}

type Result<T> = std::result::Result<T, self::Error>;

fn main() {

    let socket = UdpSocket::bind("0.0.0.0:53").unwrap();

    loop {
        let mut recv_buf = [0u8; 512];
        let (_, src_addr) = socket.recv_from(&mut recv_buf).unwrap();
    
        let dns = DnsRequest::parse(&recv_buf).unwrap();
        println!("{dns:X?}");
    
        let mut send_buf = [0u8; 512];
        let res_len = dns.response(&mut send_buf).unwrap();
    
        socket.send_to(&send_buf[..res_len], src_addr).unwrap();
    }

}

/// Struct for storing the data from a DNS query inside a [DnsRequest]
#[derive(Debug)]
struct Query{
    domain_name: [u8; 253],
    domain_name_len: usize,
    ty: u16,
    class: u16,
}

/// Struct for storing the data from a DNS Request
#[derive(Debug)]
struct DnsRequest {
    transaction_id: [u8; 2],
    flags: u16,
    questions: u16,
    answer_records: u16,
    authority_records: u16,
    additional_records: u16,
    query: Query,
}

impl DnsRequest {

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
            }
        })
    }

    /// Takes a [u8; 512] buffer and writes the response based on the requests
    fn response(self, buf: &mut [u8; 512]) -> Result<usize> {

        let mut buf_ptr = 0;

        // This is the data to be added to our send buffer using a helper
        // function that keeps track of lengths
        let fields = [
            // Transaction Id
            &self.transaction_id,
            // Flags
            &Self::DNS_FLAG_RESPONSE.to_be_bytes(),
            // Questions
            &self.questions.to_be_bytes(),
            // Answers in packet (TODO)
            &[0, 1],
            // Authority Records in packet (TODO)
            &[0, 0],
            // Additional Records in packet (TODO)
            &[0, 0],
            // Query - Domain Name
            &self.query.domain_name[..self.query.domain_name_len],
            // Query - Type
            &self.query.ty.to_be_bytes(),
            // Query - Class
            &self.query.class.to_be_bytes(),
            // Answer (TODO)
            &[
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x26, 0x00, 0x04, 0x8e, 0xfa, 0xc8, 0x03
            ],
        ];

        for field in fields {
            Self::append_to_buffer(buf, &mut buf_ptr, field);
        }

        Ok(buf_ptr)
    }

    fn append_to_buffer(buf: &mut [u8; 512], buf_ptr: &mut usize, bytes: &[u8]){
        let bytes_len = bytes.len();
        buf[*buf_ptr .. *buf_ptr + bytes_len].copy_from_slice(&bytes);
        *buf_ptr += bytes_len;
    }
}

