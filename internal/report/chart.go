package report

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"slices"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"

	"github.com/thomaskhub/loglantern/internal/store"
)

const (
	chartW, chartH = 1000, 720
	scale          = 2 // lines are drawn at 2x and averaged down (anti-aliasing)
)

var (
	ink    = color.RGBA{0x1f, 0x29, 0x37, 0xff}
	muted  = color.RGBA{0x6b, 0x72, 0x80, 0xff}
	grid   = color.RGBA{0xe5, 0xe7, 0xeb, 0xff}
	bg     = color.RGBA{0xff, 0xff, 0xff, 0xff}
	colors = []color.RGBA{
		{0x25, 0x63, 0xeb, 0xff}, {0xdc, 0x26, 0x26, 0xff}, {0x05, 0x96, 0x69, 0xff}, {0xd9, 0x77, 0x06, 0xff},
		{0x7c, 0x3a, 0xed, 0xff}, {0x0e, 0x74, 0x90, 0xff}, {0xdb, 0x27, 0x77, 0xff}, {0x65, 0xa3, 0x0d, 0xff},
	}
)

type panel struct {
	title            string
	key, used, total string // a ready percentage series, or used/total raw series
	single           bool   // the series is not a minute series of cpu: nothing special, kept for clarity
}

var panels = []panel{
	{title: "CPU %", key: "cpu.cpu_p"},
	{title: "Memory %", key: "mem.used_pct", used: "mem.Mem.used", total: "mem.Mem.total"},
	{title: "Swap %", key: "mem.swap_pct", used: "mem.Swap.used", total: "mem.Swap.total"},
	{title: "Disk % (/)", key: "disk.used_pct"},
}

// Chart draws one PNG for the hosts of one environment: CPU, memory, swap and disk as four panels
// (0-100 %), one line per host, the last 24 hours up to now. loc only formats the time axis.
func Chart(ctx context.Context, st *store.Store, env string, hosts []store.Host, loc *time.Location, now time.Time) ([]byte, error) {
	hosts = slices.Clone(hosts)
	slices.SortFunc(hosts, func(a, b store.Host) int { return strings.Compare(a.Host, b.Host) })
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Host
	}
	short := shortNames(env, names)
	from := now.Add(-24 * time.Hour)

	big := image.NewRGBA(image.Rect(0, 0, chartW*scale, chartH*scale))
	draw.Draw(big, big.Bounds(), image.NewUniform(bg), image.Point{}, draw.Src)

	const (
		left, right = 52, 36
		top         = 40
		legendH     = 50
		gapX, gapY  = 36, 40
	)
	pw := (chartW - left - right - gapX) / 2
	ph := (chartH - top - legendH - gapY - 20) / 2
	var boxes [4]image.Rectangle
	for i := range panels {
		x := left + (i%2)*(pw+gapX)
		y := top + 14 + (i/2)*(ph+gapY)
		boxes[i] = image.Rect(x, y, x+pw, y+ph)
	}

	// grid and lines at 2x
	for i, p := range panels {
		b := boxes[i]
		for _, v := range []float64{0, 25, 50, 75, 100} {
			y := b.Max.Y - int(v/100*float64(b.Dy()))
			line(big, b.Min.X, y, b.Max.X, y, grid, 1)
		}
		for h := 0; h <= 24; h += 6 {
			x := b.Min.X + h*b.Dx()/24
			line(big, x, b.Min.Y, x, b.Max.Y, grid, 1)
		}
		for hi, h := range hosts {
			pts, err := panelSeries(ctx, st, h, p, from, now)
			if err != nil {
				return nil, err
			}
			c := colors[hi%len(colors)]
			px, py := -1, -1
			var last time.Time
			for _, pt := range pts {
				x := b.Min.X + int(pt.T.Sub(from).Seconds()/(24*3600)*float64(b.Dx()))
				y := b.Max.Y - int(math.Min(math.Max(pt.V, 0), 100)/100*float64(b.Dy()))
				if px >= 0 && pt.T.Sub(last) <= 10*time.Minute { // a gap longer than 10 min stays a gap
					line(big, px, py, x, y, c, 2)
				}
				px, py, last = x, y, pt.T
			}
		}
	}

	img := downscale(big, scale)
	// text at 1x
	text(img, 12, 20, fmt.Sprintf("%s  -  last 24 h up to %s", strings.ToUpper(env), now.In(loc).Format("2006-01-02 15:04 MST")), ink)
	for i, p := range panels {
		b := boxes[i]
		text(img, b.Min.X, b.Min.Y-5, p.title, ink)
		for _, v := range []int{0, 50, 100} {
			y := b.Max.Y - v*b.Dy()/100
			text(img, b.Min.X-30, y+4, fmt.Sprintf("%3d", v), muted)
		}
		for h := 0; h <= 24; h += 6 {
			x := b.Min.X + h*b.Dx()/24
			lbl := now.In(loc).Add(-time.Duration(24-h) * time.Hour).Format("15:04")
			dx := 16
			if h == 24 {
				dx = 32 // keep the last label inside its panel
			}
			text(img, x-dx, b.Max.Y+14, lbl, muted)
		}
		strokeRect(img, b, grid)
	}
	// legend
	x, y := left, chartH-legendH+28
	for i := range hosts {
		w := 7*len(short[i]) + 34
		if x+w > chartW-right {
			x, y = left, y+18
		}
		fill(img, image.Rect(x, y-8, x+18, y-5), colors[i%len(colors)])
		text(img, x+24, y, short[i], ink)
		x += w
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// panelSeries returns the minute values of one panel for a host: the ready percentage series, else used/total.
func panelSeries(ctx context.Context, st *store.Store, h store.Host, p panel, from, to time.Time) ([]store.Point, error) {
	pts, err := st.Series(ctx, h.Env, h.Host, p.key, from, to)
	if err != nil || len(pts) > 0 || p.used == "" {
		return pts, err
	}
	u, err := st.Series(ctx, h.Env, h.Host, p.used, from, to)
	if err != nil || len(u) == 0 {
		return nil, err
	}
	t, err := st.Series(ctx, h.Env, h.Host, p.total, from, to)
	if err != nil || len(t) == 0 {
		return nil, err
	}
	tm := make(map[int64]float64, len(t))
	for _, q := range t {
		tm[q.T.Unix()] = q.V
	}
	var out []store.Point
	for _, q := range u {
		if tot := tm[q.T.Unix()]; tot > 0 {
			out = append(out, store.Point{T: q.T, V: q.V / tot * 100})
		}
	}
	return out, nil
}

func line(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA, w int) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	r := w * scale / 2
	for {
		fill(img, image.Rect(x0*scale-r, y0*scale-r, x0*scale+r+1, y0*scale+r+1), c)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func fill(img *image.RGBA, r image.Rectangle, c color.RGBA) {
	draw.Draw(img, r.Intersect(img.Bounds()), image.NewUniform(c), image.Point{}, draw.Src)
}

func strokeRect(img *image.RGBA, r image.Rectangle, c color.RGBA) {
	fill(img, image.Rect(r.Min.X, r.Min.Y, r.Max.X+1, r.Min.Y+1), c)
	fill(img, image.Rect(r.Min.X, r.Max.Y, r.Max.X+1, r.Max.Y+1), c)
	fill(img, image.Rect(r.Min.X, r.Min.Y, r.Min.X+1, r.Max.Y+1), c)
	fill(img, image.Rect(r.Max.X, r.Min.Y, r.Max.X+1, r.Max.Y+1), c)
}

func downscale(src *image.RGBA, k int) *image.RGBA {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx()/k, b.Dy()/k))
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			var r, g, bl int
			for j := 0; j < k; j++ {
				for i := 0; i < k; i++ {
					c := src.RGBAAt(x*k+i, y*k+j)
					r, g, bl = r+int(c.R), g+int(c.G), bl+int(c.B)
				}
			}
			n := k * k
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(bl / n), 0xff})
		}
	}
	return dst
}

func text(img *image.RGBA, x, y int, s string, c color.RGBA) {
	d := font.Drawer{Dst: img, Src: image.NewUniform(c), Face: basicfont.Face7x13, Dot: fixed.P(x, y)}
	d.DrawString(s)
}
