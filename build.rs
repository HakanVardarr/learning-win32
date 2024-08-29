fn main() {
    if !cfg!(target_os = "windows") {
        panic!("This library only supports Windows.");
    }
}
