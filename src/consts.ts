import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: 'hxuu',
  description:
    'Knowledge spreader and cybersecurity enthusiast based in Algeria.',
  href: 'https://hxuu.github.io',
  author: 'hxuu',
  locale: 'en-US',
  featuredPostCount: 2,
  postsPerPage: 5,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/',
    label: 'Home',
  },
  {
    href: '/blog',
    label: 'Blog',
  },
  {
    href: '/work',
    label: 'Work',
  },
  {
    href: '/about',
    label: 'About',
  },
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/hxuu',
    label: 'GitHub',
  },
  {
    href: 'https://twitter.com/hxuu0',
    label: 'Twitter',
  },
  {
    href: 'https://www.youtube.com/@_mokhtari',
    label: 'Youtube',
  },
  {
    href: 'https://www.linkedin.com/in/anas-mokhtari/',
    label: 'LinkedIn',
  },
  {
    href: 'mailto:an.mokhtari@esi-sba.dz',
    label: 'Email',
  },
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Youtube: 'lucide:youtube',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}
