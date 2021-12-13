import { makeAutoObservable } from "mobx";
import { clearPersistedStore, hydrateStore, makePersistable, stopPersisting } from 'mobx-persist-store';

class ConfigStore {
    config = {
        token: "",
        endpoint: ""
    };

    constructor() {
        makeAutoObservable(this);
        makePersistable(this, { name: 'configStore', properties: ['config'], storage: window.localStorage });
    }

    setToken(token: string) {
        this.config.token = token;
    }
    setEndpoint(endpoint: string) {
        this.config.endpoint = endpoint;
    }


    async hydrateStore() {
        await hydrateStore(this);
    }

    async clearPersistedData(): Promise<void> {
        await clearPersistedStore(this);
    }

    disposePersist(): void {
        stopPersisting(this);
    }
}

const configStore = new ConfigStore();

export default configStore;
