export default {
  build: {
    lib: {
      entry: 'src/content.ts',
      formats: ['iife'],
      name: 'SecureGuardContent',
      fileName: () => 'content.js',
    },
    outDir: 'dist',
    emptyOutDir: false,
    sourcemap: true,
    target: 'es2022',
  },
};
