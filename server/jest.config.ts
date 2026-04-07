import type { Config } from 'jest';

const config: Config = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    testMatch: ['**/*.test.ts'],
    globals: {
        'ts-jest': {
            tsconfig: {
                strict: true,
                esModuleInterop: true,
            },
        },
    },
};

export default config;
