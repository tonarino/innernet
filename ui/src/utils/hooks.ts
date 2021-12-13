import { useEffect, useRef } from 'react';
import axios from 'axios';
import type { AxiosInstance } from 'axios';
import configStore from '../stores/ConfigStore';


export const useAxios = () => {
    const axiosInstance = useRef<AxiosInstance>();

    useEffect(() => {
        console.log("INIT:", configStore.config.endpoint)
        axiosInstance.current = axios.create({
            baseURL: configStore.config.endpoint,
            headers: {
                "X-Innernet-Server-Key": `${configStore.config.token}`,
            },
        });

        return () => {
            axiosInstance.current = undefined;
        };
    }, [configStore.config]);

    return axiosInstance;
};