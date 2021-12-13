import { ReactNode } from 'react';
import {
    Box,
    Flex,
    Image,
    Button,
    useColorModeValue,
    Stack,
    useColorMode,
    Circle,
} from '@chakra-ui/react';
import { MoonIcon, SunIcon } from '@chakra-ui/icons';
import favicon from "../favicon.svg";

export default function Nav() {
    const { colorMode, toggleColorMode } = useColorMode();
    return (
        <>
            <Box bg={useColorModeValue('gray.100', 'gray.900')} px={4}>
                <Flex h={16} alignItems={'center'} justifyContent={'space-between'}>
                    <Circle
                        bg="white"
                        size='30px'
                    ><Image
                            borderRadius='full'
                            boxSize='20px'
                            src={favicon}
                            alt='Dan Abramov'
                        />
                    </Circle>
                    <Flex alignItems={'center'}>
                        <Stack direction={'row'} spacing={7}>
                            <Button onClick={toggleColorMode}>
                                {colorMode === 'light' ? <MoonIcon /> : <SunIcon />}
                            </Button>
                        </Stack>
                    </Flex>
                </Flex>
            </Box>
        </>
    );
}
