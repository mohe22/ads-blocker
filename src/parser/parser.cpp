#include "../../include/parser/parser.hpp"
#include <print>


namespace DNS::Parser {

    std::expected<std::vector<uint8_t>, Error>
    Name::encode(const std::string& name,
                 std::unordered_map<std::string, uint16_t>* table,
                 uint16_t baseOffset) noexcept {
        std::vector<uint8_t> buf;
        size_t pos = 0;

        while (true) {
            std::string remaining = name.substr(pos);

            // check compression table for this suffix
            if (table) {
                auto it = table->find(remaining);
                if (it != table->end()) {
                    uint16_t ptr = it->second;
                    buf.push_back(0xC0 | ((ptr >> 8) & 0x3F));
                    buf.push_back(ptr & 0xFF);
                    return buf;
                }
                // register this suffix
                (*table)[remaining] = static_cast<uint16_t>(baseOffset + buf.size());
            }

            // end of name
            if (pos >= name.size()) {
                buf.push_back(0x00);
                break;
            }

            size_t dot      = name.find('.', pos);
            size_t labelEnd = (dot == std::string::npos) ? name.size() : dot;
            size_t labelLen = labelEnd - pos;

            if (labelLen == 0 || labelLen > Limits::MAX_LABEL_LEN)
                return std::unexpected(Error::ENCODE_LABEL_TOO_LONG);

            buf.push_back(static_cast<uint8_t>(labelLen));
            for (size_t i = pos; i < labelEnd; i++)
                buf.push_back(static_cast<uint8_t>(name[i]));

            pos = (dot == std::string::npos) ? name.size() : dot + 1;
        }

        if (buf.size() > Limits::MAX_NAME_LEN)
            return std::unexpected(Error::ENCODE_NAME_TOO_LONG);

        return buf;
    }
    std::expected<std::string, Error>
    Name::decode(const uint8_t* data, size_t len, size_t& offset) noexcept{
        std::string name;
        size_t pos =offset; //local reading offset.
        bool jumped =false; // did we flow pointer
        int  hops = 0;  // guard against pointer loops
        while(true){
            if (pos >= len)
                 return std::unexpected(Error::PARSE_TRUNCATED);
            uint8_t labelLen = data[pos];
            // end of name
            if (labelLen == 0) {
                if (!jumped) offset = pos + 1;  // advance caller past the null byte
                break;
            }

            // handle pointer
            if ((labelLen & Limits::COMPRESSION_MASK) == Limits::COMPRESSION_MASK){
                if (pos + 1 >= len)
                    return std::unexpected(Error::PARSE_PTR_OOB);

                   // pointer offset is the lower 6 bits of first byte + all of second byte
                uint16_t ptr = ((static_cast<uint16_t>(labelLen & 0x3F)) << 8) | data[pos + 1];

                if (ptr >= len)
                    return std::unexpected(Error::PARSE_PTR_OOB);

                if (!jumped) offset = pos + 2;  // advance caller past the 2-byte pointer
                jumped = true;
                pos= ptr;

                if (++hops > 20)
                    return std::unexpected(Error::PARSE_PTR_LOOP);

                continue;
            };
            //  normal label
            if(labelLen > Limits::MAX_LABEL_LEN){
                 return std::unexpected(Error::PARSE_BAD_LABEL);
            }
            pos ++; // skip the label length.
            // 1 + 11 = 11 > 15
            if (pos + labelLen > len)
                    return std::unexpected(Error::PARSE_TRUNCATED);
            // do not add a dot in the first label
            if (!name.empty()) name += '.';
            name.append(reinterpret_cast<const char*>(data + pos), labelLen);
            pos+=labelLen;

            if (name.size() > Limits::MAX_NAME_LEN)
                return std::unexpected(Error::PARSE_NAME_TOO_LONG);

        }
        return name;
    }

    // Question


    std::expected<std::vector<uint8_t>, Error>
    Question::encode(std::unordered_map<std::string, uint16_t>* table,
                     uint16_t baseOffset) const noexcept {

        auto nameBytes = Name::encode(qname_, table, baseOffset);
        if (!nameBytes) return std::unexpected(nameBytes.error());

        std::vector<uint8_t> buf = std::move(*nameBytes);

        // qtype
        buf.push_back((static_cast<uint16_t>(qtype_) >> 8) & 0xFF);
        buf.push_back( static_cast<uint16_t>(qtype_)       & 0xFF);
        // qclass
        buf.push_back((static_cast<uint16_t>(qclass_) >> 8) & 0xFF);
        buf.push_back( static_cast<uint16_t>(qclass_)       & 0xFF);

        return buf;
    }


    std::expected<Question,Error> Question::decode(const uint8_t* data, size_t len, size_t& offset) noexcept {
        std::expected<std::string, Error> name = Name::decode(data, len, offset);

        if (!name) return std::unexpected(name.error());
        // need 4 more bytes for qtype + qclass
         if (offset + 4 > len)
             return std::unexpected(Error::PARSE_TRUNCATED);
         uint16_t qtype  = (static_cast<uint16_t>(data[offset])  << 8) | data[offset + 1];
         uint16_t qclass = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
         offset += 4;

         Question q;
         q.setName(*name);
         q.setQtype(static_cast<QType> (qtype));
         q.setQclass(static_cast<QClass>(qclass));
         return q;

    }

    void Question::print() const noexcept {
        std::println("=== Question ===");
        std::println("Name    : {}", qname_);

        switch (qtype_) {
            case QType::A:     std::println("QType   : A (1)");     break;
            case QType::NS:    std::println("QType   : NS (2)");    break;
            case QType::CNAME: std::println("QType   : CNAME (5)"); break;
            case QType::SOA:   std::println("QType   : SOA (6)");   break;
            case QType::MX:    std::println("QType   : MX (15)");   break;
            case QType::TXT:   std::println("QType   : TXT (16)");  break;
            case QType::AAAA:  std::println("QType   : AAAA (28)"); break;
            case QType::SRV:   std::println("QType   : SRV (33)");  break;
            case QType::ANY:   std::println("QType   : ANY (255)"); break;
            default:           std::println("QType   : OTHER ({})", static_cast<uint16_t>(qtype_)); break;
        }

        switch (qclass_) {
            case QClass::IN_:  std::println("QClass  : IN (1)");    break;
            case QClass::CS:   std::println("QClass  : CS (2)");    break;
            case QClass::CH:   std::println("QClass  : CH (3)");    break;
            case QClass::HS:   std::println("QClass  : HS (4)");    break;
            case QClass::ANY:  std::println("QClass  : ANY (255)"); break;
            default:           std::println("QClass  : OTHER ({})", static_cast<uint16_t>(qclass_)); break;
        }

        std::println("================");
    }




    const void Header::print() const noexcept {
        std::println("=== DNS Header ===");
        std::println("ID      : 0x{:04X}", id_);
        std::println("QR      : {}", qr_ ? "Response (1)" : "Query (0)");

        switch (opcode_) {
            case OpCode::QUERY:  std::println("Opcode  : QUERY (0)");  break;
            case OpCode::IQUERY: std::println("Opcode  : IQUERY (1)"); break;
            case OpCode::STATUS: std::println("Opcode  : STATUS (2)"); break;
            case OpCode::NOTIFY: std::println("Opcode  : NOTIFY (4)"); break;
            case OpCode::UPDATE: std::println("Opcode  : UPDATE (5)"); break;
            case OpCode::DSO:    std::println("Opcode  : DSO (6)");    break;
            default:             std::println("Opcode  : UNKNOWN");    break;
        }

        std::println("AA      : {}", aa_);
        std::println("TC      : {}", tc_);
        std::println("RD      : {}", rd_);
        std::println("RA      : {}", ra_);
        std::println("AD      : {}", ad_);
        std::println("CD      : {}", cd_);

        switch (rcode_) {
            case RCode::NOERROR_: std::println("RCode   : NOERROR (0)");  break;
            case RCode::FORMERR:  std::println("RCode   : FORMERR (1)");  break;
            case RCode::SERVFAIL: std::println("RCode   : SERVFAIL (2)"); break;
            case RCode::NXDOMAIN: std::println("RCode   : NXDOMAIN (3)"); break;
            case RCode::NOTIMP:   std::println("RCode   : NOTIMP (4)");   break;
            case RCode::REFUSED:  std::println("RCode   : REFUSED (5)");  break;
            default:              std::println("RCode   : OTHER ({})", static_cast<int>(rcode_)); break;
        }

        std::println("Flags   : 0x{:04X}", getRawFlags());
        std::println("QDCount : {}", qdcount_);
        std::println("ANCount : {}", ancount_);
        std::println("NSCount : {}", nscount_);
        std::println("ARCount : {}", arcount_);
        std::println("==================");
    }

    // ResourceRecord

    std::expected<std::vector<uint8_t>, Error>
    ResourceRecord::encode(std::unordered_map<std::string, uint16_t>* table,
                           uint16_t baseOffset) const noexcept {

        auto nameBytes = Name::encode(name_, table, baseOffset);
        if (!nameBytes) return std::unexpected(nameBytes.error());

        std::vector<uint8_t> buf = std::move(*nameBytes);

        auto write16 = [&](uint16_t v) {
            buf.push_back((v >> 8) & 0xFF);
            buf.push_back( v       & 0xFF);
        };
        auto write32 = [&](uint32_t v) {
            buf.push_back((v >> 24) & 0xFF);
            buf.push_back((v >> 16) & 0xFF);
            buf.push_back((v >>  8) & 0xFF);
            buf.push_back( v        & 0xFF);
        };

        write16(static_cast<uint16_t>(type_));
        write16(static_cast<uint16_t>(rclass_));
        write32(ttl_);
        write16(static_cast<uint16_t>(rdata_.size()));  // rdlength from actual rdata

        buf.insert(buf.end(), rdata_.begin(), rdata_.end());

        return buf;
    }


    std::expected<ResourceRecord, Error>
    ResourceRecord::decode(const uint8_t* data, size_t len, size_t& offset) noexcept{
        std::expected<std::string, Error> name = Name::decode(data, len, offset);
        if (!name) return std::unexpected(name.error());
        // type + class + ttl + rdlength (10 bytes)
        if (offset + 10 > len)
            return std::unexpected(Error::PARSE_TRUNCATED);
        uint16_t type     = (static_cast<uint16_t>(data[offset])     << 8) | data[offset + 1];
         uint16_t rclass   = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
         uint32_t ttl      = (static_cast<uint32_t>(data[offset + 4]) << 24) |
                             (static_cast<uint32_t>(data[offset + 5]) << 16) |
                             (static_cast<uint32_t>(data[offset + 6]) <<  8) |
                              static_cast<uint32_t>(data[offset + 7]);
         uint16_t rdlength = (static_cast<uint16_t>(data[offset + 8]) << 8) | data[offset + 9];
         if (offset + rdlength > len)
                return std::unexpected(Error::PARSE_TRUNCATED);

         offset+=10;

         std::vector<uint8_t> rdata(
             data + offset, // from
             data + offset + rdlength // to
         );
         offset += rdlength;
         ResourceRecord rr;
         rr.setName(name.value());
         rr.setType(static_cast<QType> (type));
         rr.setRclass(static_cast<QClass>(rclass));
         rr.setTtl(ttl);
         rr.setRdlength(rdlength);
         rr.setRdata(rdata);

         return rr;
    }


    std::expected<std::vector<uint8_t>, Error> Header::encode() const noexcept {
        std::vector<uint8_t> buf;
        buf.reserve(12);

        auto write16 = [&](uint16_t v) {
            buf.push_back((v >> 8) & 0xFF);
            buf.push_back( v       & 0xFF);
        };

        write16(id_);
        write16(getRawFlags());
        write16(qdcount_);
        write16(ancount_);
        write16(nscount_);
        write16(arcount_);

        return buf;  // always exactly 12 bytes
    }
    std::expected<Header, Error> Header::decode(const uint8_t* data, size_t len) {

        if (!data || len < 12)
            return std::unexpected(DNS::Error::PARSE_TOO_SHORT);

        Header header;

        header.id_ = ntohs(*reinterpret_cast<const uint16_t*>(data));

        uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));

        // Bit 6 of the flags is reserved by the RFC and must always be 0
        if (flags & Flags::Z)
            return std::unexpected(DNS::Error::PARSE_TRUNCATED);

        bool   qr     = (flags >> 15) & 0x1;
        OpCode opcode = static_cast<OpCode>((flags >> 11) & 0xF);
        RCode  rcode  = static_cast<RCode>(flags & 0xF);

        // Opcode is 4 bits so it could hold values 0–15.
        if (opcode != OpCode::QUERY  &&
            opcode != OpCode::IQUERY &&
            opcode != OpCode::STATUS &&
            opcode != OpCode::NOTIFY &&
            opcode != OpCode::UPDATE && opcode != OpCode::DSO)
            return std::unexpected(DNS::Error::PARSE_BAD_OPCODE);

        bool ra = (flags & Flags::RA) != 0;
        bool aa = (flags & Flags::AA) != 0;

        //AA (Authoritative Answer) — only a server can set this, only in a response
        // RA (Recursion Available) — only a server sets this, only in a response
        if (!qr && (ra || aa))
            return std::unexpected(DNS::Error::PARSE_TRUNCATED);

        header.setQr    (qr);
        header.setOpcode(opcode);
        header.setAa    (aa);
        header.setTc    ((flags & Flags::TC) != 0);
        header.setRd    ((flags & Flags::RD) != 0);
        header.setRa    (ra);
        header.setAd    ((flags & Flags::AD) != 0);
        header.setCd    ((flags & Flags::CD) != 0);
        header.setRcode (rcode);

        uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
        uint16_t ancount = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
        uint16_t nscount = ntohs(*reinterpret_cast<const uint16_t*>(data + 8));
        uint16_t arcount = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));

        // must have question
        if (!qr && qdcount == 0)
            return std::unexpected(DNS::Error::PARSE_BAD_QDCOUNT);
        // The DNS spec technically allows multiple questions, but in practice no real resolver sends more than 1.
        if (qdcount > 1)
            return std::unexpected(DNS::Error::PARSE_BAD_QDCOUNT);

        // sanity caps on answer/authority/additional sections
        if (ancount > 500 || nscount > 500 || arcount > 500)
            return std::unexpected(DNS::Error::PARSE_TRUNCATED);

        header.setQuestions  (qdcount);
        header.setAnswers    (ancount);
        header.setAuthorities(nscount);
        header.setAdditionals(arcount);

        return header;
}

    std::expected<Message, DNS::Error> MessageParser::parse(const uint8_t* data, size_t len) {
        if (!data || len < 12)
            return std::unexpected(DNS::Error::PARSE_TOO_SHORT);


        if (len > Limits::MAX_EDNS_PAYLOAD)
            return std::unexpected(DNS::Error::PARSE_TRUNCATED);

        Message msg;
        std::expected<Header,Error> hdr = Header::decode(data, len);
        if (!hdr)
            return std::unexpected(hdr.error());
        msg.setHeader(hdr.value());

        size_t offset = 12;
        for (int i = 0; i < hdr.value().getQuestions(); i++ ) {
            std::expected<Question,Error> question = Question::decode(data,len, offset);
            if (!question)
                return std::unexpected(question.error());
            msg.addQuestion(question.value());
        }

        for (int i = 0; i < hdr.value().getAnswers(); i++) {
            std::expected<ResourceRecord,Error>  rr = ResourceRecord::decode(data, len, offset);
            if (!rr) return std::unexpected(rr.error());
            msg.addAnswer(rr.value());
        }

        for (int i = 0; i < hdr.value().getAuthorities(); i++) {
            std::expected<ResourceRecord,Error>  rr = ResourceRecord::decode(data, len, offset);
            if (!rr) return std::unexpected(rr.error());
            msg.addAuthority(rr.value());
        }

        for (int i = 0; i < hdr.value().getAdditionals(); i++) {
            std::expected<ResourceRecord,Error>  rr = ResourceRecord::decode(data, len, offset);
            if (!rr) return std::unexpected(rr.error());
            msg.addAdditional(rr.value());
        }

        return msg;
    }


    std::expected<std::vector<uint8_t>, DNS::Error>
    MessageParser::encode(Message& msg) noexcept {


        Header hdr = msg.getHeader();
        hdr.setQuestions  (static_cast<uint16_t>(msg.getQuestions().size()));
        hdr.setAnswers    (static_cast<uint16_t>(msg.getAnswers().size()));
        hdr.setAuthorities(static_cast<uint16_t>(msg.getAuthority().size()));
        hdr.setAdditionals(static_cast<uint16_t>(msg.getAdditional().size()));

        auto hdrBytes = hdr.encode();
        if (!hdrBytes) return std::unexpected(hdrBytes.error());

        std::vector<uint8_t> buf = std::move(*hdrBytes);

        // compression table, we need it to keep track of
        // names with their location
        std::unordered_map<std::string, uint16_t> table;

        // questions
        for (const auto& q : msg.getQuestions()) {
            auto bytes = q.encode(&table, static_cast<uint16_t>(buf.size()));
            if (!bytes) return std::unexpected(bytes.error());
            buf.insert(buf.end(), bytes->begin(), bytes->end());
        }

        // answers
        for (const auto& rr : msg.getAnswers()) {
            auto bytes = rr.encode(&table, static_cast<uint16_t>(buf.size()));
            if (!bytes) return std::unexpected(bytes.error());
            buf.insert(buf.end(), bytes->begin(), bytes->end());
        }

        // authority
        for (const auto& rr : msg.getAuthority()) {
            auto bytes = rr.encode(&table, static_cast<uint16_t>(buf.size()));
            if (!bytes) return std::unexpected(bytes.error());
            buf.insert(buf.end(), bytes->begin(), bytes->end());
        }

        // additional
        for (const auto& rr : msg.getAdditional()) {
            auto bytes = rr.encode(&table, static_cast<uint16_t>(buf.size()));
            if (!bytes) return std::unexpected(bytes.error());
            buf.insert(buf.end(), bytes->begin(), bytes->end());
        }

        if (buf.size() > Limits::MAX_EDNS_PAYLOAD)
            return std::unexpected(Error::ENCODE_OVERFLOW);

        return buf;
    }
} // namespace DNS::Parser
