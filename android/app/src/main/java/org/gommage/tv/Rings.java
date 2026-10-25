package org.gommage.tv;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

/**
 * The desktop app's dotted rings, reshaped to hug the sideways switch: five dotted outlines below the track
 * whose colour and rhythm follow the state (idle wave, connecting sweep, connected pulse, error alarm).
 */
public class Rings extends View {
    static final float[] FADE = {1f, .78f, .58f, .4f, .26f}; // outer rings fainter, as on desktop
    private final Paint dot = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF r = new RectF();
    private final float d;
    private int state; // 0 idle, 1 connecting, 2 connected, 3 error
    private float trackW = 230, trackH = 98; // dp; the phone layout's switch stands upright

    public Rings(Context c, AttributeSet a) {
        super(c, a);
        d = getResources().getDisplayMetrics().density;
        dot.setStyle(Paint.Style.STROKE);
        dot.setStrokeWidth(3 * d);
        dot.setStrokeCap(Paint.Cap.ROUND);
    }

    void setTrack(float wDp, float hDp) {
        trackW = wDp;
        trackH = hDp;
    }

    void setState(int s) {
        state = s;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas c) {
        float t = (System.nanoTime() / 1e6f) / 1000f;
        float cx = getWidth() / 2f, cy = getHeight() / 2f;
        int color = state == 2 ? 0xFF6CF0A8 : state == 3 ? 0xFFFF6B6B : state == 1 ? 0xFFF7B955 : 0xFFFFFFFF;
        c.save();
        c.clipRect(0, cy, getWidth(), getHeight()); // lower half only, like desktop
        for (int i = 0; i < 5; i++) {
            float o = FADE[i], a;
            if (state == 2) a = wave(t / 2.4f - i * .075f, .35f, o * .45f, o);
            else if (state == 3) a = wave(t / 1.3f, .5f, o * .2f, o * .85f);
            else if (state == 1) a = o * .4f;
            else a = wave(t / 3.6f - i * .05f, .4f, o * .25f, o * .6f);
            ring(c, i, color, a, cx, cy);
            if (state == 1) { // connecting: a bright band sweeps right to left over the same dots
                float x = getWidth() * (1.1f - (t / 1.5f % 1f) * 1.2f);
                c.save();
                c.clipRect(x - 40 * d, cy, x + 40 * d, getHeight());
                ring(c, i, 0xFFFFD38A, o, cx, cy);
                c.restore();
            }
        }
        c.restore();
        postInvalidateOnAnimation();
    }

    private void ring(Canvas c, int i, int color, float alpha, float cx, float cy) {
        float off = (16 + 12 * i) * d, hw = trackW / 2 * d + off, hh = trackH / 2 * d + off;
        r.set(cx - hw, cy - hh, cx + hw, cy + hh);
        dot.setPathEffect(new DashPathEffect(new float[]{0, (8.2f + .4f * i) * d}, 0));
        dot.setColor(color);
        dot.setAlpha(Math.round(alpha * 255));
        float corner = Math.min(hw, hh);
        c.drawRoundRect(r, corner, corner, dot);
    }

    /** Smooth rise to hi at peak (fraction of the period), back to lo. */
    private static float wave(float phase, float peak, float lo, float hi) {
        float p = phase - (float) Math.floor(phase);
        float k = p < peak ? p / peak : (1 - p) / (1 - peak);
        k = k * k * (3 - 2 * k);
        return lo + (hi - lo) * k;
    }
}
