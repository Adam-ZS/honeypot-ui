import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowLeft, CheckCircle, KeyRound, ShieldAlert } from 'lucide-react'
import { api } from '../services/api'

const MIN_PASSWORD_LENGTH = 12

// Declared at module scope: components defined inside a render are recreated
// on every render, which remounts their whole subtree and loses input focus.
function Shell({ children }) {
  return (
    <div className="min-h-screen grid-bg flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-slide-up">
        <div className="flex items-center gap-3 mb-10 justify-center">
          <ShieldAlert className="text-accent-cyan w-8 h-8" />
          <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan">
            HoneySentinel
          </span>
        </div>
        <div className="bg-surface-800 border border-border rounded-xl p-8">{children}</div>
      </div>
    </div>
  )
}

function FieldError({ message }) {
  if (!message) return null
  return (
    <p className="mt-1.5 flex items-center gap-1 text-xs text-accent-red font-mono">
      <AlertCircle className="w-3 h-3" /> {message}
    </p>
  )
}

/**
 * Password reset.
 *
 * The backend has exposed /auth/request-password-reset and /auth/reset-password
 * from the start, but nothing in the UI reached them, so a user who forgot
 * their password had no way back in.
 */
export default function ForgotPassword() {
  const navigate = useNavigate()
  const [step, setStep] = useState('request')
  const [email, setEmail] = useState('')
  const [otpCode, setOtpCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)

  const inputClass = (key) =>
    `w-full bg-surface-700 border rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 font-mono outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
      errors[key] ? 'border-accent-red' : 'border-border focus:border-accent-blue'
    }`

  const handleRequest = async (event) => {
    event.preventDefault()
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErrors({ email: 'Enter a valid email address.' })
      return
    }
    setLoading(true)
    try {
      await api.auth.requestPasswordReset(email)
      setErrors({})
      setStep('confirm')
    } catch (err) {
      setErrors({ email: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async (event) => {
    event.preventDefault()
    const next = {}
    if (otpCode.length !== 6) next.otp = 'Enter the 6-digit code.'
    if (password.length < MIN_PASSWORD_LENGTH) {
      next.password = `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`
    }
    if (password !== confirm) next.confirm = 'Passwords do not match.'
    if (Object.keys(next).length) {
      setErrors(next)
      return
    }

    setLoading(true)
    try {
      await api.auth.resetPassword({
        email,
        otp_code: otpCode,
        new_password: password,
      })
      setStep('done')
    } catch (err) {
      setErrors({ otp: err.message })
    } finally {
      setLoading(false)
    }
  }

  if (step === 'done') {
    return (
      <Shell>
        <div className="text-center">
          <CheckCircle className="w-14 h-14 text-accent-green mx-auto mb-6" />
          <h1 className="text-2xl font-semibold text-white mb-2">Password updated</h1>
          <p className="text-sm text-gray-400 mb-8 font-mono">
            You can now sign in with your new password.
          </p>
          <button
            type="button"
            onClick={() => navigate('/login')}
            className="bg-accent-cyan hover:bg-cyan-300 text-surface-900 font-semibold text-sm rounded-lg px-8 py-2.5 transition-all font-mono tracking-wider uppercase"
          >
            Sign in
          </button>
        </div>
      </Shell>
    )
  }

  if (step === 'confirm') {
    return (
      <Shell>
        <button
          type="button"
          onClick={() => setStep('request')}
          className="flex items-center gap-1 text-xs font-mono text-gray-500 hover:text-gray-300 mb-6 transition-colors"
        >
          <ArrowLeft className="w-3 h-3" /> Back
        </button>

        <div className="flex items-center gap-2 mb-1">
          <KeyRound className="w-5 h-5 text-accent-cyan" />
          <h1 className="text-2xl font-semibold text-white">Set a new password</h1>
        </div>
        <p className="text-sm text-gray-500 mb-6 font-mono">
          If an account exists for {email}, we sent it a 6-digit code.
        </p>

        <form onSubmit={handleConfirm} noValidate className="space-y-5">
          <div>
            <label htmlFor="otp" className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
              Reset code
            </label>
            <input
              id="otp"
              inputMode="numeric"
              maxLength={6}
              placeholder="000000"
              value={otpCode}
              onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
              className={`${inputClass('otp')} text-center text-2xl tracking-[0.5em]`}
            />
            <FieldError message={errors.otp} />
          </div>

          <div>
            <label htmlFor="new-password" className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
              New password
            </label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClass('password')}
            />
            <FieldError message={errors.password} />
          </div>

          <div>
            <label htmlFor="confirm-password" className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
              Confirm password
            </label>
            <input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={inputClass('confirm')}
            />
            <FieldError message={errors.confirm} />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent-cyan hover:bg-cyan-300 disabled:opacity-50 text-surface-900 font-semibold text-sm rounded-lg py-2.5 transition-all font-mono tracking-wider uppercase"
          >
            {loading ? 'Updating...' : 'Update password'}
          </button>
        </form>
      </Shell>
    )
  }

  return (
    <Shell>
      <h1 className="text-2xl font-semibold text-white mb-1">Reset your password</h1>
      <p className="text-sm text-gray-500 mb-8 font-mono">
        We&apos;ll email you a code to set a new one.
      </p>

      <form onSubmit={handleRequest} noValidate className="space-y-5">
        <div>
          <label htmlFor="reset-email" className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
            Email address
          </label>
          <input
            id="reset-email"
            type="email"
            autoComplete="email"
            placeholder="analyst@soc.internal"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={inputClass('email')}
          />
          <FieldError message={errors.email} />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-accent-blue hover:bg-blue-400 disabled:opacity-50 text-surface-900 font-semibold text-sm rounded-lg py-2.5 transition-all font-mono tracking-wider uppercase"
        >
          {loading ? 'Sending...' : 'Send reset code'}
        </button>
      </form>

      <p className="mt-6 text-center text-xs text-gray-500 font-mono">
        <Link to="/login" className="text-accent-cyan hover:underline">
          Back to sign in
        </Link>
      </p>
    </Shell>
  )
}
