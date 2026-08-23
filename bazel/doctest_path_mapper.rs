//! Proc-macro marker that exposes the exec-configuration root to rust_doc_test.

extern crate proc_macro;

use proc_macro::TokenStream;

/// Returns its input unchanged. Doctests never invoke this macro; its declared
/// executable is used only so rules_rust can remap hermetic linker paths.
#[proc_macro]
pub fn rustleaks_doctest_path_mapper(input: TokenStream) -> TokenStream {
    input
}
