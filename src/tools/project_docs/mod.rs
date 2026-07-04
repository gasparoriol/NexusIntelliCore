mod data;
mod format;
mod i18n;
#[allow(clippy::module_inception)]
mod project_docs;
mod render;

pub(super) use project_docs::generate_project_docs;

#[cfg(test)]
mod tests {
    #[test]
    fn reexported_generate_project_docs_is_visible() {
        // Compile-time guard: if the re-export disappears or visibility narrows,
        // this reference will fail to compile.
        let _ = super::generate_project_docs;
    }
}
