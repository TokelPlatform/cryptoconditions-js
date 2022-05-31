### Notes on 'cryptoconditions' library

This is the 'cryptoconditions' library for Komodo cc modules development.

Dev language: rust, with wasm support

For use in a js app this lib could be compiled as a wasm module with the wasm-pack, use this cmd to build a wasm:

`wasm-pack build --target nodejs`

See pkg/cryptoconditions_bs.js for supported javascript cryptoconditions api.

### Use as a global module
To add the wasm to your nodejs project first make it as a global node module:
```
cd ~/your-repo-dir/cryptoconditions-js/cryptoconditions/pkg
npm link -g
```
then make a link to the global npm module for your project
```
cd ~/your-project-dir
npm link cryptoconditions
```

### Use as a local module
Add a link to this repo into your package.json:
```
  "dependencies": {
    "cryptoconditions-js": "git+https://github.com/dimxy/cryptoconditions-js.git#master",
    ...
  }
```

### Use in browser
To use the cryptoconditions wasm in browser:

* Build a wasm with `wasm-pack build` cmd
* Use browserify tool to create a js module usable in a web app

