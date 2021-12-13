import { Box, Button, Circle, Container, FormControl, FormHelperText, FormLabel, Image, Input } from '@chakra-ui/react';
import { SetStateAction, useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import Nav from '../components/nav';
import configStore from '../stores/ConfigStore';
import favicon from "../favicon.svg";

const ConfigPage = () => {
    const history = useHistory();
    const [endpoint, setEndpoint] = useState(window.location.origin)
    const [token, setToken] = useState("")

    useEffect(() => {
        configStore.hydrateStore().then(() => {
            if (configStore.config.token !== "") {
                // Config token has been hydrated from localstorage
                history.push('/server');
            }
        })
    })


    const handleChangeEndpoint = (event: { target: { value: SetStateAction<string>; }; }) => setEndpoint(event.target.value)
    const handleChangeToken = (event: { target: { value: SetStateAction<string>; }; }) => setToken(event.target.value)

    const authenticate = () => {
        configStore.setEndpoint(endpoint);
        configStore.setToken(token)
        history.push('/server');
    }


    return (
        <>
            <Nav></Nav>
            <Container maxW='container.lg' centerContent>

                <div className='flex gap-2 p-10 content-center w-screen items-center justify-center h-30'>
                    <p className='inline-block align-middle  text-blue-500 underline decoration-yellow-400 decoration-2 text-4xl font-semibold'>innernet</p>
                    <Circle
                        bg="white"
                        size='40px'
                        className='align-middle'
                    ><Image
                            borderRadius='full'
                            boxSize='30px'
                            src={favicon}
                            alt='Dan Abramov'
                        />
                    </Circle>
                </div >

                <form onSubmit={authenticate}>
                    <Box p={4}>
                        <FormControl id='server-key' isRequired>
                            <FormLabel>Innernert Server key</FormLabel>
                            <Input placeholder='ex: 0jYksHFHyQGkznbVhFuRAOiycy7o...' value={token}
                                onChange={handleChangeToken} />
                            <FormHelperText>[server] public-key, found in /etc/innernet/inteface.conf on your peer</FormHelperText>
                        </FormControl>

                        <FormControl id='server-endpoint' isRequired className='pt-6'>
                            <FormLabel>Server Endpoint</FormLabel>
                            <Input value={endpoint}
                                onChange={handleChangeEndpoint} />
                            <FormHelperText>You shouldnt need to change this</FormHelperText>
                        </FormControl>
                    </Box>
                    <div className='pt-6 float-right'>
                        <Button type='submit'>
                            Authenticate
                        </Button>
                    </div>
                </form>
            </Container >
        </>
    )
}

export default ConfigPage