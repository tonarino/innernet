import { Peer } from "../model/shared/Peer";

export default function PeerComponent(peer: Peer) {

    return (
        <div>{peer.id} - {peer.name}</div>
    )
}