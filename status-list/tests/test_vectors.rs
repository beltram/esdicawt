use status_list::{RawStatus, StatusBits, StatusList};
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[wasm_bindgen_test::wasm_bindgen_test]
fn one_bit_status_list() {
    let expected = "a2646269747301636c737458bd78daeddc010dc0200c0041a88249400ad2903e0f4b
ba00bd93f002beb7a2a2010000a91e09000000000000000000000000000000807296
04000000000000000000000000000000000000000000000000000000000000000000
000000000000005c6f4800000000000000fc2c240000000000000000000000be1b12
000000000000000000ecaa4b000000000000000000000000000000009b0b09000000
00000000000038de9400000000000000002a30cc010000000080642f0bd8011b"
        .lines()
        .collect::<String>();

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    #[repr(u8)]
    enum Status {
        Valid = 0x00,
        Revoked = 0x01,
    }

    impl status_list::Status for Status {
        const BITS: StatusBits = StatusBits::One;

        fn is_valid(&self) -> bool {
            matches!(self, Self::Valid)
        }
    }
    impl From<Status> for u8 {
        fn from(s: Status) -> Self {
            s as Self
        }
    }
    impl From<u8> for Status {
        fn from(s: u8) -> Self {
            match s {
                0x00 => Self::Valid,
                0x01 => Self::Revoked,
                _ => unreachable!(),
            }
        }
    }

    let mut status_list = StatusList::<Status>::with_capacity(1 << 20, None);

    assert!(status_list.set(0, Status::Revoked).is_some());
    assert!(status_list.set(1993, Status::Revoked).is_some());
    assert!(status_list.set(25460, Status::Revoked).is_some());
    assert!(status_list.set(159495, Status::Revoked).is_some());
    assert!(status_list.set(495669, Status::Revoked).is_some());
    assert!(status_list.set(554353, Status::Revoked).is_some());
    assert!(status_list.set(645645, Status::Revoked).is_some());
    assert!(status_list.set(723232, Status::Revoked).is_some());
    assert!(status_list.set(854545, Status::Revoked).is_some());
    assert!(status_list.set(934534, Status::Revoked).is_some());
    assert!(status_list.set(1000345, Status::Revoked).is_some());

    let mut buf = vec![];
    ciborium::into_writer(&status_list, &mut buf).unwrap();
    let encoded = hex::encode(buf);

    assert_eq!(expected, encoded);
}

#[test]
#[wasm_bindgen_test::wasm_bindgen_test]
fn two_bit_status_list() {
    let expected = "a2646269747302636c737459013d78daeddb310d00211000412ea1a04004fe5520ed
357c28c81d3312b6df68bc65480000000000406e2101000000000000000000000000
0000000000000000000000000000000000000040795b020000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
0080f4ba0400000000000000000000000000406d764a000000000000000000000000
000000000000000000e0922101000000000000000000000000000000000000fc1312
00000000000000000000000000000000000000000000000000000000000000c0912e
01000000000000000000000000000000000000c07d4b020000000000000000000000
00000000a8614a0000000000000000000000406a1fcd60010c"
        .lines()
        .collect::<String>();

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    #[repr(u8)]
    enum Status {
        Valid = 0x00,
        Revoked = 0x01,
        Suspended = 0x02,
        Undefined = 0x03,
    }

    impl status_list::Status for Status {
        const BITS: StatusBits = StatusBits::Two;

        fn is_valid(&self) -> bool {
            matches!(self, Self::Valid)
        }
    }
    impl From<Status> for u8 {
        fn from(s: Status) -> Self {
            s as Self
        }
    }
    impl From<u8> for Status {
        fn from(s: u8) -> Self {
            match s {
                0x00 => Self::Valid,
                0x01 => Self::Revoked,
                0x02 => Self::Suspended,
                0x03 => Self::Undefined,
                _ => unreachable!(),
            }
        }
    }

    let mut status_list = StatusList::<Status>::with_capacity(1 << 21, None);

    assert!(status_list.set(0, Status::Revoked).is_some());
    assert!(status_list.set(1993, Status::Suspended).is_some());
    assert!(status_list.set(25460, Status::Revoked).is_some());
    assert!(status_list.set(159495, Status::Undefined).is_some());
    assert!(status_list.set(495669, Status::Revoked).is_some());
    assert!(status_list.set(554353, Status::Revoked).is_some());
    assert!(status_list.set(645645, Status::Suspended).is_some());
    assert!(status_list.set(723232, Status::Revoked).is_some());
    assert!(status_list.set(854545, Status::Revoked).is_some());
    assert!(status_list.set(934534, Status::Suspended).is_some());
    assert!(status_list.set(1000345, Status::Undefined).is_some());

    let mut buf = vec![];
    ciborium::into_writer(&status_list, &mut buf).unwrap();
    let encoded = hex::encode(buf);

    assert_eq!(expected, encoded);
}

#[test]
#[wasm_bindgen_test::wasm_bindgen_test]
fn four_bit_status_list() {
    let expected = "a2646269747304636c737459024878daedd0410d8030100030081f0226908204244c
025290840414111cecb7e4b8b5123a0e40669b020000000000000000000000000000
0020b549010000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
0000000000400ebb0200000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
000000000000e8c5a100000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000082280a00000000000000000000000000
00000000000000000000000000000000000000000000000000000000000080ae9c0a
00000000000000000000000000000000000000000000000000000000000000000000
000000686a5640339702000000008865510000000000000000000000000000000000
00000000000000000000000000000071dc0a0080ba55010000000000000000000000
c0cf3daf03000000000000000008ec03dc4c04c0"
        .lines()
        .collect::<String>();

    let mut status_list = StatusList::<RawStatus<4>>::with_capacity(1 << 22, None);

    status_list.set(0, 1);
    status_list.set(1993, 2);
    status_list.set(35460, 3);
    status_list.set(459495, 4);
    status_list.set(595669, 5);
    status_list.set(754353, 6);
    status_list.set(845645, 7);
    status_list.set(923232, 8);
    status_list.set(924445, 9);
    status_list.set(934534, 10);
    status_list.set(1004534, 11);
    status_list.set(1000345, 12);
    status_list.set(1030203, 13);
    status_list.set(1030204, 14);
    status_list.set(1030205, 15);

    let mut buf = vec![];
    ciborium::into_writer(&status_list, &mut buf).unwrap();
    let encoded = hex::encode(buf);

    assert_eq!(expected, encoded);
}

#[test]
#[wasm_bindgen_test::wasm_bindgen_test]
fn eight_bit_status_list() {
    let expected = "a2646269747308636c73745907b078daedd1639033691886d1ac6ddbb66ddbb66ddb
b66ddbb66ddbb68d59d4d66cbe496626e94e5e9c53d57fbb9ef7ba2b158028ec2401
000090bae724000052b6a504000000000000b4deb0120004ef5409000000008af087
040000000001db400200000000000022f09004000000000000000000946857090000
80789c24010000000000000050bcbe240000005a62700900000000000008c0c01200
000074eb2c09a032900404697e09000000000000000000000000000000a8e74b0900
000000000000e89171240000000080024d2a0100006db79a04000000000040b0de95
0042f7a00400000000000000ddb84e02000000ca34af0400108b0f24a078ef480040
6fec2501108e372568c6d31264e77409000000e8d60d129098b7240000000000b2b0
b604406727480000000010a28525000048d799120081f94402202c1f4b0010b8fd25
2019934800004098ce91a0b6d3248012cc22010040217e970000000000006aba4f02
00000000000068997d4afbf304e2020055a69080607d280100000034e82b09000000
00000000d2b4af040000b4de00120000000000000000c558550200000032339a0440
031e96004230880400ddb85c020000000068ad312488dc151200408e1e9000e881eb
250000000000b23795040000291a55028ad6bf040000000000000090a46d24000000
00008026dc2c01746d7509000000a05d369180e0ec260100000000407a3694000000
00000000000000004af5b90400005d3a560200000000000000a8369e040010aa0324
00000000006881032500000000001af3b3040000108b0b2500000000000000000000
000032b3b204000089e92ffa172c6344a09dee90000000000020694b490000000000
000000000000000000000000000000f0b7ed3bbe3564000000803cbc2a0140504692
0000000092f7be040059d85c020000a011c34940e8d69400000088da8e120000599b
5e0200ba32bb040000fce719092067074b000010ba472500000000000000000080a6
cc2a010000000000000000000000000000409fb696000000000000000000000a7697
0400000000e4ee230900000000000000006a7b4d0202719b0411b84c02008050dd2a
01405c269600000000000000000000000000a00943047bd976c601000000a021874b
0000000000005080ef2400000000000000000000201a3349000000b95b4402008277
980400c46c31090000ea785202c8d905120000d11b590200000000689137240080c0
0d2a01404856928096985b02200fa748909ca12400000000002004fd4a00000074e9
7809000000000000f8cb641200006d7446dacf9bcfc200404c4e96000000000088d0
6012fccf94120000000040d83e950000202c8f48000000d09073250008c70f1200d0
b83d2500008070ec2d0100000040412e9600000080b8cd16cda5fd180b0080047c21
019466590900006881e32400a0b65b24000028cdbd12000000545b5f020000000000
00000000000000000000000000a0c3b7120000000055969300a0795b490000d080b1
2520274b4bd06a8748d05b2f480065f951020080446d24417366960080062c240100
00004076e69200000000000000000000a0587d4b000000000000358d98e4aba6316c
12869180329c17d435771b0400000000000000000000000080f67a49020000000000
000080284c2e0100000000000000a9995002c2b6a904000000000000f4e975090000
00a86f5b09000080b0fd22010000000000000000000000000000404d7b4800000000
00000000404f1d210100000094e66d0980387d2f01d06151090028d2021200e4e037
0982f38d04000000000000000000000000000000509c9d25f8d73c12000000000000
00000000000064e96c09000000000000000000000000a86f1409000080fa4e940000
200f37490000356c1cf47523180800000000000080bac69200000000000000000000
0000000000000000000000a872950400908f192500000000000000a047c694000000
0000204c1349407656940000b2b7bb04000000d0d974120000000000000000000040
fbcc2001000000000000a5384a02a052d94102000000000000000080c08c2f0104e7
59092027734a00891a5d82b04d2d010000d0bd752500000000000008d43a12000000
000000000000000064ea79090000000000000000000028cf121234eb270900000000
0000a872a40450b8152400000028c35312542a0b4a000000a9ba51020080d27d2601
00000000401b3c260140932e95000000000000000048d93512000000000000000000
00000000000000f08faf25a025869400000000007aefce327e3aa0aeb9594b0288cf
f01240afbd2c4195432580205d2d01000000000000000000b4c9f212000000000014
e34a0900000000000000e8adcd24000000000000803a8e9600000000000000000000
c8c2fd120000000000000000000000c1b95d022055434b0000000040008e91000000
006230ad0484640b09000068b9172500000000a0c3af12000000346e490980588c2b
0100000000007432870464ee1e090000000000000000206ad74a000094623d090000
0000000000000042739104b4c5251200000000908683240000009af29e0400000000
00000000003df284040000000000000040b6ce9720598f4b40a2f693002018af4800
000000f1da4502000000000000000000c8c72a120000000000000000000000d0168b
4b0040b3fe04353d7f81"
        .lines()
        .collect::<String>();

    let mut status_list = StatusList::<RawStatus<8>>::with_capacity(1 << 23, None);

    status_list.set(233478, 0);
    status_list.set(52451, 1);
    status_list.set(576778, 2);
    status_list.set(513575, 3);
    status_list.set(468106, 4);
    status_list.set(292632, 5);
    status_list.set(214947, 6);
    status_list.set(182323, 7);
    status_list.set(884834, 8);
    status_list.set(66653, 9);
    status_list.set(62489, 10);
    status_list.set(196493, 11);
    status_list.set(458517, 12);
    status_list.set(487925, 13);
    status_list.set(55649, 14);
    status_list.set(416992, 15);
    status_list.set(879796, 16);
    status_list.set(462297, 17);
    status_list.set(942059, 18);
    status_list.set(583408, 19);
    status_list.set(13628, 20);
    status_list.set(334829, 21);
    status_list.set(886286, 22);
    status_list.set(713557, 23);
    status_list.set(582738, 24);
    status_list.set(326064, 25);
    status_list.set(451545, 26);
    status_list.set(705889, 27);
    status_list.set(214350, 28);
    status_list.set(194502, 29);
    status_list.set(796765, 30);
    status_list.set(202828, 31);
    status_list.set(752834, 32);
    status_list.set(721327, 33);
    status_list.set(554740, 34);
    status_list.set(91122, 35);
    status_list.set(963483, 36);
    status_list.set(261779, 37);
    status_list.set(793844, 38);
    status_list.set(165255, 39);
    status_list.set(614839, 40);
    status_list.set(758403, 41);
    status_list.set(403258, 42);
    status_list.set(145867, 43);
    status_list.set(96100, 44);
    status_list.set(477937, 45);
    status_list.set(606890, 46);
    status_list.set(167335, 47);
    status_list.set(488197, 48);
    status_list.set(211815, 49);
    status_list.set(797182, 50);
    status_list.set(582952, 51);
    status_list.set(950870, 52);
    status_list.set(765108, 53);
    status_list.set(341110, 54);
    status_list.set(776325, 55);
    status_list.set(745056, 56);
    status_list.set(439368, 57);
    status_list.set(559893, 58);
    status_list.set(149741, 59);
    status_list.set(358903, 60);
    status_list.set(513405, 61);
    status_list.set(342679, 62);
    status_list.set(969429, 63);
    status_list.set(795775, 64);
    status_list.set(566121, 65);
    status_list.set(460566, 66);
    status_list.set(680070, 67);
    status_list.set(117310, 68);
    status_list.set(480348, 69);
    status_list.set(67319, 70);
    status_list.set(661552, 71);
    status_list.set(841303, 72);
    status_list.set(561493, 73);
    status_list.set(138807, 74);
    status_list.set(442463, 75);
    status_list.set(659927, 76);
    status_list.set(445910, 77);
    status_list.set(1046963, 78);
    status_list.set(829700, 79);
    status_list.set(962282, 80);
    status_list.set(299623, 81);
    status_list.set(555493, 82);
    status_list.set(292826, 83);
    status_list.set(517215, 84);
    status_list.set(551009, 85);
    status_list.set(898490, 86);
    status_list.set(837603, 87);
    status_list.set(759161, 88);
    status_list.set(459948, 89);
    status_list.set(290102, 90);
    status_list.set(1034977, 91);
    status_list.set(190650, 92);
    status_list.set(98810, 93);
    status_list.set(229950, 94);
    status_list.set(320531, 95);
    status_list.set(335506, 96);
    status_list.set(885333, 97);
    status_list.set(133227, 98);
    status_list.set(806915, 99);
    status_list.set(800313, 100);
    status_list.set(981571, 101);
    status_list.set(527253, 102);
    status_list.set(24077, 103);
    status_list.set(240232, 104);
    status_list.set(559572, 105);
    status_list.set(713399, 106);
    status_list.set(233941, 107);
    status_list.set(615514, 108);
    status_list.set(911768, 109);
    status_list.set(331680, 110);
    status_list.set(951527, 111);
    status_list.set(6805, 112);
    status_list.set(552366, 113);
    status_list.set(374660, 114);
    status_list.set(223159, 115);
    status_list.set(625884, 116);
    status_list.set(417146, 117);
    status_list.set(320527, 118);
    status_list.set(784154, 119);
    status_list.set(338792, 120);
    status_list.set(1199, 121);
    status_list.set(679804, 122);
    status_list.set(1024680, 123);
    status_list.set(40845, 124);
    status_list.set(234603, 125);
    status_list.set(761225, 126);
    status_list.set(644903, 127);
    status_list.set(502167, 128);
    status_list.set(121477, 129);
    status_list.set(505144, 130);
    status_list.set(165165, 131);
    status_list.set(179628, 132);
    status_list.set(1019195, 133);
    status_list.set(145149, 134);
    status_list.set(263738, 135);
    status_list.set(269256, 136);
    status_list.set(996739, 137);
    status_list.set(346296, 138);
    status_list.set(555864, 139);
    status_list.set(887384, 140);
    status_list.set(444173, 141);
    status_list.set(421844, 142);
    status_list.set(653716, 143);
    status_list.set(836747, 144);
    status_list.set(783119, 145);
    status_list.set(918762, 146);
    status_list.set(946835, 147);
    status_list.set(253764, 148);
    status_list.set(519895, 149);
    status_list.set(471224, 150);
    status_list.set(134272, 151);
    status_list.set(709016, 152);
    status_list.set(44112, 153);
    status_list.set(482585, 154);
    status_list.set(461829, 155);
    status_list.set(15080, 156);
    status_list.set(148883, 157);
    status_list.set(123467, 158);
    status_list.set(480125, 159);
    status_list.set(141348, 160);
    status_list.set(65877, 161);
    status_list.set(692958, 162);
    status_list.set(148598, 163);
    status_list.set(499131, 164);
    status_list.set(584009, 165);
    status_list.set(1017987, 166);
    status_list.set(449287, 167);
    status_list.set(277478, 168);
    status_list.set(991262, 169);
    status_list.set(509602, 170);
    status_list.set(991896, 171);
    status_list.set(853666, 172);
    status_list.set(399318, 173);
    status_list.set(197815, 174);
    status_list.set(203278, 175);
    status_list.set(903979, 176);
    status_list.set(743015, 177);
    status_list.set(888308, 178);
    status_list.set(862143, 179);
    status_list.set(979421, 180);
    status_list.set(113605, 181);
    status_list.set(206397, 182);
    status_list.set(127113, 183);
    status_list.set(844358, 184);
    status_list.set(711569, 185);
    status_list.set(229153, 186);
    status_list.set(521470, 187);
    status_list.set(401793, 188);
    status_list.set(398896, 189);
    status_list.set(940810, 190);
    status_list.set(293983, 191);
    status_list.set(884749, 192);
    status_list.set(384802, 193);
    status_list.set(584151, 194);
    status_list.set(970201, 195);
    status_list.set(523882, 196);
    status_list.set(158093, 197);
    status_list.set(929312, 198);
    status_list.set(205329, 199);
    status_list.set(106091, 200);
    status_list.set(30949, 201);
    status_list.set(195586, 202);
    status_list.set(495723, 203);
    status_list.set(348779, 204);
    status_list.set(852312, 205);
    status_list.set(1018463, 206);
    status_list.set(1009481, 207);
    status_list.set(448260, 208);
    status_list.set(841042, 209);
    status_list.set(122967, 210);
    status_list.set(345269, 211);
    status_list.set(794764, 212);
    status_list.set(4520, 213);
    status_list.set(818773, 214);
    status_list.set(556171, 215);
    status_list.set(954221, 216);
    status_list.set(598210, 217);
    status_list.set(887110, 218);
    status_list.set(1020623, 219);
    status_list.set(324632, 220);
    status_list.set(398244, 221);
    status_list.set(622241, 222);
    status_list.set(456551, 223);
    status_list.set(122648, 224);
    status_list.set(127837, 225);
    status_list.set(657676, 226);
    status_list.set(119884, 227);
    status_list.set(105156, 228);
    status_list.set(999897, 229);
    status_list.set(330160, 230);
    status_list.set(119285, 231);
    status_list.set(168005, 232);
    status_list.set(389703, 233);
    status_list.set(143699, 234);
    status_list.set(142524, 235);
    status_list.set(493258, 236);
    status_list.set(846778, 237);
    status_list.set(251420, 238);
    status_list.set(516351, 239);
    status_list.set(83344, 240);
    status_list.set(171931, 241);
    status_list.set(879178, 242);
    status_list.set(663475, 243);
    status_list.set(546865, 244);
    status_list.set(428362, 245);
    status_list.set(658891, 246);
    status_list.set(500560, 247);
    status_list.set(557034, 248);
    status_list.set(830023, 249);
    status_list.set(274471, 250);
    status_list.set(629139, 251);
    status_list.set(958869, 252);
    status_list.set(663071, 253);
    status_list.set(152133, 254);
    status_list.set(19535, 255);

    let mut buf = vec![];
    ciborium::into_writer(&status_list, &mut buf).unwrap();
    let encoded = hex::encode(buf);

    assert_eq!(expected, encoded);
}
