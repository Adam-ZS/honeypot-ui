import { Component } from 'react'

export default class ErrorBoundary extends Component {
  state = { failed: false }

  static getDerivedStateFromError() { return { failed: true } }

  render() {
    if (this.state.failed) {
      return (
        <div role="alert" className="panel mx-auto max-w-xl p-6">
          <h1 className="text-xl">This view could not be loaded</h1>
          <p className="my-3 text-paper-2">Reload to try again. If the problem continues, open another view from the navigation.</p>
          <button className="control control-primary" onClick={() => window.location.reload()}>Reload page</button>
        </div>
      )
    }
    return this.props.children
  }
}
