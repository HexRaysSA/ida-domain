/*
 * Minimal binary with real structure and enum usage.
 *
 * Tests can declare the same Packet/PacketStatus types in the database and
 * apply them to g_packet; the compiler-generated member accesses below then
 * operate on typed data (e.g. they surface as xrefs to individual members).
 */

enum PacketStatus {
    STATUS_READY = 42,
    STATUS_ERROR = 99,
};

struct Packet {
    char *text;                /* offset 0  */
    unsigned int length;       /* offset 8  */
    enum PacketStatus status;  /* offset 12 */
};

struct Packet g_packet = { 0, 1, STATUS_ERROR };

void reset_packet(void) {
    g_packet.text = 0;
    g_packet.length = 0;
    g_packet.status = STATUS_READY;
}

unsigned int packet_size(void) {
    return g_packet.length;
}

void set_status(struct Packet *p, enum PacketStatus s) {
    p->status = s;
}
