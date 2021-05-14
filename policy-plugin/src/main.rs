use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::Cursor;

// if return non zero, route will be rejected
#[no_mangle]
pub fn apply(ptr: i32, len: i32) -> i32 {
    let bin = unsafe { ::std::slice::from_raw_parts(ptr as *const u8, len as _) };
    println!("policy implemented in WebAssembly");
    let mut c = Cursor::new(bin);
    while c.position() < len as u64 {
        let _type = c.read_u8().unwrap();
        for _ in 0..c.read_u8().unwrap() {
            let n = c.read_u32::<NetworkEndian>().unwrap();
            if n == 65000 {
                return 1;
            }
        }
    }
    0
}

fn main() {
    println!("Hello, world!");
}
