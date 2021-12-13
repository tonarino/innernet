const colors = require('tailwindcss/colors')

module.exports = {
    mode: 'jit',
    purge: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
    darkMode: "media",
    theme: {
        extend: {
            animation: {
                'spin-slow': 'spin 3s linear infinite',
            },
            fontFamily: {
                'sans': ['Roboto', 'Helvetica', 'Arial', 'sans-serif'],
            },
            colors: {
                blue: colors.sky,
            }

        }
    },
    variants: {
        extend: {},
    },
    plugins: [
        require('@tailwindcss/typography'),
    ],
}