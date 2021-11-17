### Notes on 'cryptoconditions' library

This is the 'cryptoconditions' library for Komodo cc modules development.

Dev language: rust

It also could be compiled as a wasm with wasm-pack, use this cmd to build a wasm:

`wasm-pack build --target nodejs`

See pkg/cryptoconditions_bs.js for supported javascript cryptoconditions api.

To add the wasm to your nodejs project first make it as a global node module:
```
cd ~/pycc/cryptoconditions/pkg
npm link -g
```
then make a link to the global npm module for your project
```
cd ~/your-project-dir
npm link cryptoconditions
```

To use the cryptoconditions wasm in browser use browserify tool


## Publish new npm version

[Reference](https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/packaging-and-publishing.html)

```
$ wasm-pack build --target nodejs
$ cd pkg
$ #check the version of the library in package.json
$ npm publish --access=public
```