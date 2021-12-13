import type { Cidr } from "./Cidr";
import type { Peer } from "./Peer";

export interface State { peers: Array<Peer>, cidrs: Array<Cidr>, }