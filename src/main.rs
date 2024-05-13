

use std::io;
use lib::{count_newlines_memmap_avx2_running_sum, get_filename};


fn main() -> io::Result<()> {
    let path = get_filename();
    unsafe {
        println!("Number of lines: {}", count_newlines_memmap_avx2_running_sum(path.as_str())?);
    }
    Ok(())

}
