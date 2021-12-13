import Nav from '../components/nav'
import { Alert, AlertIcon, Button } from '@chakra-ui/react'
import { useAxios } from '../utils/hooks'
import { useState } from "react"
import { Peer } from '../model/shared/Peer'
import configStore from "../stores/ConfigStore"
import PeerComponent from '../components/peer'
import { useHistory } from 'react-router-dom'
import { State } from '../model/shared/State'


export default () => {
    const history = useHistory();
    const axiosInstance = useAxios();
    const [peers, setPeers] = useState<Peer[]>([]);
    const [state, setState] = useState<State>();
    const [errors, setErrors] = useState<any>([]);

    const getPeers = () => {
        !!axiosInstance.current && axiosInstance.current.get<[Peer]>('/v1/admin/peers').then(response => {
            setPeers(response.data)
            setErrors({ peers: null, ...errors })
        }, error => {
            setErrors({ peers: error, ...errors })
        });
    };


    const getState = () => {
        !!axiosInstance.current && axiosInstance.current.get<State>('/v1/user/state').then(response => {
            setState(response.data)
            setErrors({ state: null, ...errors })
        }, error => {
            setErrors({ state: error, ...errors })
        });
    };

    const clearConfig = () => {
        configStore.clearPersistedData().then(() => {
            configStore.setEndpoint("");
            configStore.setToken("");
            history.push('/auth');
        });
    }

    return (
        <div>
            <Nav></Nav>
            <div className='p-10 w-full'>

                <div className='p-4 bg-gray-100 w-full rounded-lg text-black'>
                    <Button colorScheme='blue' className='float-right' onClick={clearConfig}>Clear</Button>
                    <p><span className='text-blue-500 underline decoration-yellow-400'>Endpoint: </span>  {configStore.config.endpoint}</p>
                    <p className='truncate w-40'><span className='text-blue-500 underline decoration-yellow-400'>Token:</span>  {configStore.config.token}</p>
                </div>

            </div>
            <div className='p-10 w-full flex flex-col gap-4'>
                <div>
                    <Button colorScheme='blue' w={150} onClick={getState}>USER API</Button>
                </div>
                {errors.state && <Alert status='error'>
                    <AlertIcon />
                    Error Loading State /v1/user/state
                </Alert>}
                {state && <div className='h-52 overflow-auto'><pre>{state ? JSON.stringify(state, null, 4) : ""}</pre></div>}
                <div>
                    <Button colorScheme='blue' w={150} onClick={getPeers}>ADMIN API</Button>
                </div>
                {errors.peers && <Alert status='error'>
                    <AlertIcon />
                    Error Loading peers /v1/admin/peers
                </Alert>}
                {peers && <div className='h-52 overflow-auto'><pre>{peers.length > 1 ? JSON.stringify(peers, null, 4) : ""}</pre></div>}
            </div >

        </div >
    )
}