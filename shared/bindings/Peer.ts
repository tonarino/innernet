import type { Hostname } from "./Hostname";
import type { Endpoint } from "./Endpoint";

export interface Peer { id: bigint, name: Hostname, ip: string, cidr_id: bigint, public_key: string, endpoint: Endpoint | null, persistent_keepalive_interval: number | null, is_admin: boolean, is_disabled: boolean, is_redeemed: boolean, invite_expires: string | null, candidates: Array<Endpoint>, }