import type { Peer } from "./Peer";
import type { Cidr } from "./Cidr";

export interface State { peers: Array<Peer>, cidrs: Array<Cidr>, }