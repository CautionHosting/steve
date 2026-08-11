// Development/test placeholder. The production esbuild graph replaces this
// module with the generated wasm-bindgen glue through a static import.
export class XWingClient {
  constructor() {
    throw new Error('X-Wing WASM bindings require a built distribution');
  }
}

export default async function initialize() {
  throw new Error('X-Wing WASM bindings require a built distribution');
}
