//! Development aid: write the worksheet sheets as PBM files (the worksheet is not secret).
use aska_paper::render::RenderOptions;
fn main() {
    let dir = std::env::args().nth(1).expect("output directory");
    let opts = RenderOptions::default();
    for (i, s) in aska_paper::worksheet::render(&opts).iter().enumerate() {
        std::fs::write(format!("{dir}/ws{i}.pbm"), s.to_pbm().as_slice()).unwrap();
    }
}
