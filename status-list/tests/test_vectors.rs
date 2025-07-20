use status_list::{RawStatus, StatusBits, StatusList, issuer::LstMut};
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

    let mut lst = LstMut::<Status>::with_capacity(2usize.pow(20));

    assert!(lst.replace(0, Status::Revoked).is_some());
    assert!(lst.replace(1993, Status::Revoked).is_some());
    assert!(lst.replace(25460, Status::Revoked).is_some());
    assert!(lst.replace(159495, Status::Revoked).is_some());
    assert!(lst.replace(495669, Status::Revoked).is_some());
    assert!(lst.replace(554353, Status::Revoked).is_some());
    assert!(lst.replace(645645, Status::Revoked).is_some());
    assert!(lst.replace(723232, Status::Revoked).is_some());
    assert!(lst.replace(854545, Status::Revoked).is_some());
    assert!(lst.replace(934534, Status::Revoked).is_some());
    assert!(lst.replace(1000345, Status::Revoked).is_some());

    let status_list = StatusList::new(lst.into(), None);

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

    let mut lst = LstMut::<Status>::with_capacity(2usize.pow(21));

    assert!(lst.replace(0, Status::Revoked).is_some());
    assert!(lst.replace(1993, Status::Suspended).is_some());
    assert!(lst.replace(25460, Status::Revoked).is_some());
    assert!(lst.replace(159495, Status::Undefined).is_some());
    assert!(lst.replace(495669, Status::Revoked).is_some());
    assert!(lst.replace(554353, Status::Revoked).is_some());
    assert!(lst.replace(645645, Status::Suspended).is_some());
    assert!(lst.replace(723232, Status::Revoked).is_some());
    assert!(lst.replace(854545, Status::Revoked).is_some());
    assert!(lst.replace(934534, Status::Suspended).is_some());
    assert!(lst.replace(1000345, Status::Undefined).is_some());

    let status_list = StatusList::new(lst.into(), None);

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

    let mut lst = LstMut::<RawStatus<4>>::with_capacity(2usize.pow(22));

    lst.replace(0, 1);
    lst.replace(1993, 2);
    lst.replace(35460, 3);
    lst.replace(459495, 4);
    lst.replace(595669, 5);
    lst.replace(754353, 6);
    lst.replace(845645, 7);
    lst.replace(923232, 8);
    lst.replace(924445, 9);
    lst.replace(934534, 10);
    lst.replace(1004534, 11);
    lst.replace(1000345, 12);
    lst.replace(1030203, 13);
    lst.replace(1030204, 14);
    lst.replace(1030205, 15);

    let status_list = StatusList::new(lst.into(), None);

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

    let mut lst = LstMut::<RawStatus<8>>::with_capacity(2usize.pow(23));

    lst.replace(233478, 0);
    lst.replace(52451, 1);
    lst.replace(576778, 2);
    lst.replace(513575, 3);
    lst.replace(468106, 4);
    lst.replace(292632, 5);
    lst.replace(214947, 6);
    lst.replace(182323, 7);
    lst.replace(884834, 8);
    lst.replace(66653, 9);
    lst.replace(62489, 10);
    lst.replace(196493, 11);
    lst.replace(458517, 12);
    lst.replace(487925, 13);
    lst.replace(55649, 14);
    lst.replace(416992, 15);
    lst.replace(879796, 16);
    lst.replace(462297, 17);
    lst.replace(942059, 18);
    lst.replace(583408, 19);
    lst.replace(13628, 20);
    lst.replace(334829, 21);
    lst.replace(886286, 22);
    lst.replace(713557, 23);
    lst.replace(582738, 24);
    lst.replace(326064, 25);
    lst.replace(451545, 26);
    lst.replace(705889, 27);
    lst.replace(214350, 28);
    lst.replace(194502, 29);
    lst.replace(796765, 30);
    lst.replace(202828, 31);
    lst.replace(752834, 32);
    lst.replace(721327, 33);
    lst.replace(554740, 34);
    lst.replace(91122, 35);
    lst.replace(963483, 36);
    lst.replace(261779, 37);
    lst.replace(793844, 38);
    lst.replace(165255, 39);
    lst.replace(614839, 40);
    lst.replace(758403, 41);
    lst.replace(403258, 42);
    lst.replace(145867, 43);
    lst.replace(96100, 44);
    lst.replace(477937, 45);
    lst.replace(606890, 46);
    lst.replace(167335, 47);
    lst.replace(488197, 48);
    lst.replace(211815, 49);
    lst.replace(797182, 50);
    lst.replace(582952, 51);
    lst.replace(950870, 52);
    lst.replace(765108, 53);
    lst.replace(341110, 54);
    lst.replace(776325, 55);
    lst.replace(745056, 56);
    lst.replace(439368, 57);
    lst.replace(559893, 58);
    lst.replace(149741, 59);
    lst.replace(358903, 60);
    lst.replace(513405, 61);
    lst.replace(342679, 62);
    lst.replace(969429, 63);
    lst.replace(795775, 64);
    lst.replace(566121, 65);
    lst.replace(460566, 66);
    lst.replace(680070, 67);
    lst.replace(117310, 68);
    lst.replace(480348, 69);
    lst.replace(67319, 70);
    lst.replace(661552, 71);
    lst.replace(841303, 72);
    lst.replace(561493, 73);
    lst.replace(138807, 74);
    lst.replace(442463, 75);
    lst.replace(659927, 76);
    lst.replace(445910, 77);
    lst.replace(1046963, 78);
    lst.replace(829700, 79);
    lst.replace(962282, 80);
    lst.replace(299623, 81);
    lst.replace(555493, 82);
    lst.replace(292826, 83);
    lst.replace(517215, 84);
    lst.replace(551009, 85);
    lst.replace(898490, 86);
    lst.replace(837603, 87);
    lst.replace(759161, 88);
    lst.replace(459948, 89);
    lst.replace(290102, 90);
    lst.replace(1034977, 91);
    lst.replace(190650, 92);
    lst.replace(98810, 93);
    lst.replace(229950, 94);
    lst.replace(320531, 95);
    lst.replace(335506, 96);
    lst.replace(885333, 97);
    lst.replace(133227, 98);
    lst.replace(806915, 99);
    lst.replace(800313, 100);
    lst.replace(981571, 101);
    lst.replace(527253, 102);
    lst.replace(24077, 103);
    lst.replace(240232, 104);
    lst.replace(559572, 105);
    lst.replace(713399, 106);
    lst.replace(233941, 107);
    lst.replace(615514, 108);
    lst.replace(911768, 109);
    lst.replace(331680, 110);
    lst.replace(951527, 111);
    lst.replace(6805, 112);
    lst.replace(552366, 113);
    lst.replace(374660, 114);
    lst.replace(223159, 115);
    lst.replace(625884, 116);
    lst.replace(417146, 117);
    lst.replace(320527, 118);
    lst.replace(784154, 119);
    lst.replace(338792, 120);
    lst.replace(1199, 121);
    lst.replace(679804, 122);
    lst.replace(1024680, 123);
    lst.replace(40845, 124);
    lst.replace(234603, 125);
    lst.replace(761225, 126);
    lst.replace(644903, 127);
    lst.replace(502167, 128);
    lst.replace(121477, 129);
    lst.replace(505144, 130);
    lst.replace(165165, 131);
    lst.replace(179628, 132);
    lst.replace(1019195, 133);
    lst.replace(145149, 134);
    lst.replace(263738, 135);
    lst.replace(269256, 136);
    lst.replace(996739, 137);
    lst.replace(346296, 138);
    lst.replace(555864, 139);
    lst.replace(887384, 140);
    lst.replace(444173, 141);
    lst.replace(421844, 142);
    lst.replace(653716, 143);
    lst.replace(836747, 144);
    lst.replace(783119, 145);
    lst.replace(918762, 146);
    lst.replace(946835, 147);
    lst.replace(253764, 148);
    lst.replace(519895, 149);
    lst.replace(471224, 150);
    lst.replace(134272, 151);
    lst.replace(709016, 152);
    lst.replace(44112, 153);
    lst.replace(482585, 154);
    lst.replace(461829, 155);
    lst.replace(15080, 156);
    lst.replace(148883, 157);
    lst.replace(123467, 158);
    lst.replace(480125, 159);
    lst.replace(141348, 160);
    lst.replace(65877, 161);
    lst.replace(692958, 162);
    lst.replace(148598, 163);
    lst.replace(499131, 164);
    lst.replace(584009, 165);
    lst.replace(1017987, 166);
    lst.replace(449287, 167);
    lst.replace(277478, 168);
    lst.replace(991262, 169);
    lst.replace(509602, 170);
    lst.replace(991896, 171);
    lst.replace(853666, 172);
    lst.replace(399318, 173);
    lst.replace(197815, 174);
    lst.replace(203278, 175);
    lst.replace(903979, 176);
    lst.replace(743015, 177);
    lst.replace(888308, 178);
    lst.replace(862143, 179);
    lst.replace(979421, 180);
    lst.replace(113605, 181);
    lst.replace(206397, 182);
    lst.replace(127113, 183);
    lst.replace(844358, 184);
    lst.replace(711569, 185);
    lst.replace(229153, 186);
    lst.replace(521470, 187);
    lst.replace(401793, 188);
    lst.replace(398896, 189);
    lst.replace(940810, 190);
    lst.replace(293983, 191);
    lst.replace(884749, 192);
    lst.replace(384802, 193);
    lst.replace(584151, 194);
    lst.replace(970201, 195);
    lst.replace(523882, 196);
    lst.replace(158093, 197);
    lst.replace(929312, 198);
    lst.replace(205329, 199);
    lst.replace(106091, 200);
    lst.replace(30949, 201);
    lst.replace(195586, 202);
    lst.replace(495723, 203);
    lst.replace(348779, 204);
    lst.replace(852312, 205);
    lst.replace(1018463, 206);
    lst.replace(1009481, 207);
    lst.replace(448260, 208);
    lst.replace(841042, 209);
    lst.replace(122967, 210);
    lst.replace(345269, 211);
    lst.replace(794764, 212);
    lst.replace(4520, 213);
    lst.replace(818773, 214);
    lst.replace(556171, 215);
    lst.replace(954221, 216);
    lst.replace(598210, 217);
    lst.replace(887110, 218);
    lst.replace(1020623, 219);
    lst.replace(324632, 220);
    lst.replace(398244, 221);
    lst.replace(622241, 222);
    lst.replace(456551, 223);
    lst.replace(122648, 224);
    lst.replace(127837, 225);
    lst.replace(657676, 226);
    lst.replace(119884, 227);
    lst.replace(105156, 228);
    lst.replace(999897, 229);
    lst.replace(330160, 230);
    lst.replace(119285, 231);
    lst.replace(168005, 232);
    lst.replace(389703, 233);
    lst.replace(143699, 234);
    lst.replace(142524, 235);
    lst.replace(493258, 236);
    lst.replace(846778, 237);
    lst.replace(251420, 238);
    lst.replace(516351, 239);
    lst.replace(83344, 240);
    lst.replace(171931, 241);
    lst.replace(879178, 242);
    lst.replace(663475, 243);
    lst.replace(546865, 244);
    lst.replace(428362, 245);
    lst.replace(658891, 246);
    lst.replace(500560, 247);
    lst.replace(557034, 248);
    lst.replace(830023, 249);
    lst.replace(274471, 250);
    lst.replace(629139, 251);
    lst.replace(958869, 252);
    lst.replace(663071, 253);
    lst.replace(152133, 254);
    lst.replace(19535, 255);

    let status_list = StatusList::new(lst.into(), None);

    let mut buf = vec![];
    ciborium::into_writer(&status_list, &mut buf).unwrap();
    let encoded = hex::encode(buf);

    assert_eq!(expected, encoded);
}
