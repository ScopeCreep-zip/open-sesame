//! Composable render pipeline

use crate::render::context::RenderContext;
use crate::util::Result;

/// A single render pass in the pipeline
pub trait RenderPass {
    /// Execute this render pass
    fn render(&self, context: &mut RenderContext) -> Result<()>;
}

/// A composable pipeline of render passes
pub struct RenderPipeline {
    passes: Vec<Box<dyn RenderPass>>,
}

impl RenderPipeline {
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Add a render pass to the pipeline
    pub fn add_pass<P: RenderPass + 'static>(mut self, pass: P) -> Self {
        self.passes.push(Box::new(pass));
        self
    }

    /// Execute all passes in order
    pub fn render(&self, context: &mut RenderContext) -> Result<()> {
        for pass in &self.passes {
            pass.render(context)?;
        }
        Ok(())
    }
}

impl Default for RenderPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct TestPass {
        executed: std::cell::Cell<bool>,
    }

    #[allow(dead_code)]
    impl RenderPass for TestPass {
        fn render(&self, _context: &mut RenderContext) -> Result<()> {
            self.executed.set(true);
            Ok(())
        }
    }

    #[test]
    fn test_pipeline_creation() {
        let pipeline = RenderPipeline::new();
        assert!(pipeline.passes.is_empty());
    }
}
