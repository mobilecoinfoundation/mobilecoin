const path = require('path')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const InterpolateHtmlPlugin = require('interpolate-html-plugin')
const CopyPlugin = require('copy-webpack-plugin')

module.exports = {
  entry: {
    bundle: path.resolve(__dirname, '..', './src/index.tsx'),
  },

  output: {
    path: path.resolve(__dirname, '..', './build'),
    filename: '[name].[contenthash].js',
    clean: true,
  },

  module: {
    rules: [
      {
        test: /\.(ts|js)x?$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [['@babel/preset-typescript', { allowNamespaces: true }]],
          },
        },
      },
      {
        test: /\.(ico|gif|png|jpg|jpeg)$/i,
        exclude: /public/,
        type: 'asset/resource',
      },
      {
        test: /\.(woff(2)?|eot|ttf|otf|svg|)$/i,
        type: 'asset/inline',
      },
    ],
  },

  plugins: [
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, '..', './src/index.html'),
    }),
    new InterpolateHtmlPlugin({
      ASSETS_URL: 'assets',
    }),
    new CopyPlugin({
      patterns: [{ from: 'public', to: 'assets' }],
    }),
  ],

  resolve: {
    modules: ['node_modules'],
    extensions: ['.tsx', '.ts', '.js'],
  },

  stats: 'errors-only',
}
