'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { cn } from '@/lib/utils'
import { Shield, Server, AlertTriangle, Database, LayoutDashboard } from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Actifs', href: '/assets', icon: Server },
  { name: 'Vulnerabilites', href: '/vulnerabilities', icon: AlertTriangle },
  { name: 'CVEs', href: '/cves', icon: Database },
]

export function Sidebar() {
  const [activePath, setActivePath] = useState('/')

  useEffect(() => {
    setActivePath(window.location.pathname)
  }, [])

  return (
    <div className="flex h-screen w-64 flex-col bg-slate-900 text-white">
      <div className="flex h-16 items-center border-b border-slate-700 px-6">
        <Shield className="mr-2 h-6 w-6 text-orange-500" />
        <span className="text-lg font-bold">CVE Tracker</span>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => {
          const isActive = activePath === item.href

          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-orange-500 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              )}
            >
              <item.icon
                className={cn(
                  'mr-3 h-5 w-5 flex-shrink-0',
                  isActive ? 'text-white' : 'text-slate-400 group-hover:text-white'
                )}
              />
              <span className="text-sm">{item.name}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-slate-700 p-4">
        <p className="text-xs text-slate-400">
          Systeme de gestion des vulnerabilites
        </p>
      </div>
    </div>
  )
}
