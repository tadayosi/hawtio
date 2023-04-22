import { hawtio, Hawtio, registerCorePlugins } from '@hawtio/react'
import { registerPlugins } from '@hawtio/react-plugins'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { configure } from './config'
import { reportWebVitals } from './reportWebVitals'

// Register builtin plugins
registerCorePlugins()
registerPlugins()

hawtio
  // Set up plugin location
  .addUrl('plugin')
  // Bootstrap Hawtio
  .bootstrap()

// Configure the console
configure()

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement)
root.render(
  <React.StrictMode>
    <Hawtio />
  </React.StrictMode>,
)

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals()
