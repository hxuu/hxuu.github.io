import {
  getAllPostsAndSubposts,
  getAllProjects,
  isSubpost,
} from '@/lib/data-utils'
import { formatDate } from '@/lib/utils'

type SearchItem = {
  title: string
  description: string
  href: string
  section: string
  date?: string
  sortDate: number
  tags: string[]
  text: string
}

export const prerender = true

const stripMarkdown = (value: string | null | undefined) =>
  (value ?? '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[>#*_~|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

export async function GET() {
  const posts = await getAllPostsAndSubposts()
  const projects = await getAllProjects()

  const postItems: SearchItem[] = posts.map((post) => ({
    title: post.data.title,
    description: post.data.description,
    href: `/blog/${post.id}`,
    section: isSubpost(post.id) ? 'Subpost' : 'Post',
    date: formatDate(post.data.date),
    sortDate: post.data.date.valueOf(),
    tags: post.data.tags ?? [],
    text: stripMarkdown(
      [
        post.id,
        post.data.title,
        post.data.description,
        ...(post.data.tags ?? []),
        post.body,
      ].join(' '),
    ),
  }))

  const projectItems: SearchItem[] = projects.map((project) => ({
    title: project.data.name,
    description: project.data.description,
    href: project.data.link,
    section: 'Project',
    date: project.data.startDate
      ? formatDate(project.data.startDate)
      : undefined,
    sortDate: project.data.startDate?.valueOf() ?? 0,
    tags: project.data.tags,
    text: stripMarkdown(
      [
        project.id,
        project.data.name,
        project.data.description,
        ...project.data.tags,
      ].join(' '),
    ),
  }))

  const searchItems = [...postItems, ...projectItems].sort(
    (a, b) => b.sortDate - a.sortDate,
  )

  return new Response(JSON.stringify(searchItems), {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
