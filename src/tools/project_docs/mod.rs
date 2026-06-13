mod data;
mod format;
mod i18n;
mod project_docs;
mod render;

pub(super) use project_docs::generate_project_docs;

#[cfg(test)]
mod tests {
    #[test]
    fn reexported_generate_project_docs_is_visible() {
        // Compile-time guard: if the re-export disappears or visibility narrows,
        // this reference will fail to compile.
        let _handler = super::generate_project_docs;
    }
}
