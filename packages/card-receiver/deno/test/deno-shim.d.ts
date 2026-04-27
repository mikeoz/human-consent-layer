// Type declarations for Deno globals.
// Used only for tsc-based type-checking outside Deno's own type system.
// Deno itself ships these types automatically; this shim is harmless under Deno.
declare global {
  namespace Deno {
    function readTextFile(path: string): Promise<string>;
    function exit(code?: number): never;
  }
}
export {};
