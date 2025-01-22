export class Proof {
    public a: Uint8Array;

    public b: Uint8Array;

    public c: Uint8Array;

    constructor(proof: Buffer) {
        this.a = new Uint8Array(proof.subarray(0, 64));
        this.b = new Uint8Array(proof.subarray(64, 192));
        this.c = new Uint8Array(proof.subarray(192, 256));
    }
}