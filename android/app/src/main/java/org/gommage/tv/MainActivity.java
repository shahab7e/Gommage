package org.gommage.tv;

import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.StateListDrawable;
import android.graphics.drawable.TransitionDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    // Same exits as the desktop app
    static final String[] NAMES = {"Any location", "Netherlands", "Germany", "France", "UK", "USA", "Canada", "Sweden",
            "Switzerland", "Finland", "Austria", "Albania", "Ukraine"};
    static final String[] CODES = {"", "nl", "de", "fr", "gb", "us", "ca", "se", "ch", "fi", "at", "al", "ua"};
    // Desktop colours per state: idle, connecting, connected, error
    static final int[][] SKY = {{0xFF353949, 0xFF2A2D39, 0xFF22242D}, {0xFF4A4535, 0xFF38342A, 0xFF2B2822},
            {0xFF5D8E78, 0xFF4A7866, 0xFF3B6453}, {0xFF4D323A, 0xFF3A262C, 0xFF2B1E22}};
    static final int[][] KNOB = {{0xFF4A505C, 0xFF383D47, 0xFF31353E}, {0xFF5A5446, 0xFF474236, 0xFF3D392F},
            {0xFF7AA792, 0xFF5E8B76, 0xFF527C69}, {0xFF4A505C, 0xFF383D47, 0xFF31353E}};
    static final int[] LED = {0xFF3EE08F, 0xFFF7B955, 0x59000000, 0xFFFF6B6B};
    static final int[] POWER = {0xFFF2F4F8, 0xFFF7B955, 0xFFD8FFE9, 0xFFF2F4F8};

    private final Handler tick = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;
    private LinearLayout flags;
    private TextView place, title, sub, knobText, hint, log;
    private View root, knob, led, identity;
    private ImageView map, power;
    private Rings rings;
    private ObjectAnimator blink;
    private int sel, shown = -1;
    private Drawable sky;
    private boolean tall; // phone in portrait: upright switch, knob slides down

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.main);
        prefs = getSharedPreferences("gommage", MODE_PRIVATE);
        root = findViewById(R.id.root);
        map = findViewById(R.id.map);
        flags = findViewById(R.id.flags);
        place = findViewById(R.id.place);
        title = findViewById(R.id.title);
        sub = findViewById(R.id.sub);
        rings = findViewById(R.id.rings);
        knob = findViewById(R.id.knob);
        knobText = findViewById(R.id.knobText);
        led = findViewById(R.id.led);
        power = findViewById(R.id.power);
        hint = findViewById(R.id.hint);
        identity = findViewById(R.id.identity);
        log = findViewById(R.id.log);
        title.setShadowLayer(dp(20), 0, dp(4), 0x40000000);
        tall = getResources().getConfiguration().orientation == android.content.res.Configuration.ORIENTATION_PORTRAIT;
        if (tall) rings.setTrack(98, 220);

        // the chevrons nudge toward where the knob will go, as on desktop
        ObjectAnimator nudge = ObjectAnimator.ofFloat(hint, tall ? "translationY" : "translationX", 0, dp(4));
        nudge.setDuration(900);
        nudge.setRepeatMode(ValueAnimator.REVERSE);
        nudge.setRepeatCount(ValueAnimator.INFINITE);
        nudge.start();
        blink = ObjectAnimator.ofFloat(led, "alpha", 1f, .35f);
        blink.setDuration(500);
        blink.setRepeatMode(ValueAnimator.REVERSE);
        blink.setRepeatCount(ValueAnimator.INFINITE);

        sel = Math.max(0, java.util.Arrays.asList(CODES).indexOf(prefs.getString("country", "")));
        flags.setOnFocusChangeListener((v, f) -> refresh());
        flags.setOnKeyListener((v, code, e) -> {
            if (e.getAction() != KeyEvent.ACTION_DOWN) return false;
            int step = code == KeyEvent.KEYCODE_DPAD_LEFT ? -1 : code == KeyEvent.KEYCODE_DPAD_RIGHT ? 1 : 0;
            if (step == 0) return false;
            sel = (sel + step + CODES.length) % CODES.length;
            prefs.edit().putString("country", CODES[sel]).apply();
            refresh();
            return true;
        });

        knob.setOnClickListener(v -> {
            if (GommageVpn.running) {
                startService(new Intent(this, GommageVpn.class).setAction(GommageVpn.STOP));
                return;
            }
            Intent ask = VpnService.prepare(this); // null once the user has allowed the VPN
            if (ask != null) startActivityForResult(ask, 1);
            else onActivityResult(1, RESULT_OK, null);
        });
        identity.setOnClickListener(v -> GommageVpn.newIdentity());
        findViewById(R.id.bridges).setOnClickListener(v -> editBridges());
        findViewById(R.id.support).setOnClickListener(v -> startActivity(new Intent(this, SupportActivity.class)));
        knob.requestFocus(); // OK on the remote connects straight away
    }

    private void editBridges() {
        EditText e = new EditText(this);
        e.setText(prefs.getString("bridges", ""));
        e.setHint("obfs4 … or webtunnel …");
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setMinLines(3);
        e.setTextSize(13);
        new AlertDialog.Builder(this)
                .setTitle("Your bridges")
                .setMessage("One per line. They're tried first on the next connect. Without them, Gommage finds public bridges itself.")
                .setView(e)
                .setPositiveButton("Save", (d, w) -> prefs.edit().putString("bridges", e.getText().toString()).apply())
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        if (result == RESULT_OK) startService(new Intent(this, GommageVpn.class));
    }

    @Override
    protected void onResume() {
        super.onResume();
        GommageVpn.onChange = () -> runOnUiThread(this::refresh);
        refresh();
    }

    @Override
    protected void onPause() {
        GommageVpn.onChange = null;
        tick.removeCallbacksAndMessages(null);
        super.onPause();
    }

    private void refresh() {
        boolean run = GommageVpn.running, on = GommageVpn.connected;
        int s = on ? 2 : run ? 1 : GommageVpn.failed ? 3 : 0;
        if (s != shown) changeState(s, shown < 0);

        // Like the desktop app, the country is picked while disconnected and the flags step aside once on
        flags.setVisibility(run ? View.INVISIBLE : View.VISIBLE);
        drawFlags();
        String country = NAMES[sel];
        place.setText(run ? (sel == 0 ? "Any location" : "Exit: " + country)
                : flags.isFocused() ? "◀   " + country + "   ▶" : country);
        identity.setVisibility(on ? View.VISIBLE : View.GONE);
        title.setText(s == 0 ? "Not connected" : s == 1 ? "Connecting…" : s == 3 ? "Couldn't connect" : clock());
        title.setTextColor(s == 3 ? 0xFFFF6B6B : 0xFFF2F4F8);
        sub.setText(s == 0 ? (flags.isFocused() ? "Left and right change the exit country"
                : tall ? "Tap the switch to connect" : "Press OK to connect") : GommageVpn.status);

        List<String> lines;
        synchronized (GommageVpn.log) {
            lines = new ArrayList<>(GommageVpn.log.subList(Math.max(0, GommageVpn.log.size() - 3), GommageVpn.log.size()));
        }
        log.setText(String.join("\n", lines));

        tick.removeCallbacksAndMessages(null);
        if (on) tick.postDelayed(this::refresh, 1000); // keeps the timer running
    }

    /** Everything that changes colour or position with the state; fades like the desktop app. */
    private void changeState(int s, boolean instant) {
        shown = s;
        boolean run = s == 1 || s == 2;
        Drawable next = skyFor(s);
        if (instant || sky == null) root.setBackground(next);
        else {
            TransitionDrawable fade = new TransitionDrawable(new Drawable[]{sky, next});
            fade.setCrossFadeEnabled(true);
            root.setBackground(fade);
            fade.startTransition(900);
        }
        sky = next;
        map.setImageAlpha(s == 2 ? 31 : 43); // the desktop map's 12% / 17% black dots

        knob.setBackground(knobFor(s));
        if (tall) knob.animate().translationY(run ? dp(84) : 0).setDuration(instant ? 0 : 550).start();
        else knob.animate().translationX(run ? dp(92) : 0).setDuration(instant ? 0 : 550).start();
        knobText.setText(run ? "STOP" : "START");
        ((GradientDrawable) led.getBackground().mutate()).setColor(LED[s]);
        if (s == 1) blink.start();
        else {
            blink.cancel();
            led.setAlpha(1f);
        }
        power.setColorFilter(POWER[s]);
        hint.setScaleX(run ? -1 : 1); // "»" mirrored, so it points and nudges back toward START
        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) hint.getLayoutParams();
        lp.gravity = tall ? Gravity.CENTER_HORIZONTAL | (run ? Gravity.TOP : Gravity.BOTTOM)
                : Gravity.CENTER_VERTICAL | (run ? Gravity.START : Gravity.END);
        hint.setLayoutParams(lp);
        hint.setVisibility(s == 1 ? View.INVISIBLE : View.VISIBLE);
        rings.setState(s);
    }

    /** Desktop sky: a vertical gradient with a soft light in the top-left corner. */
    private Drawable skyFor(int s) {
        GradientDrawable base = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, SKY[s]);
        GradientDrawable glow = new GradientDrawable();
        glow.setGradientType(GradientDrawable.RADIAL_GRADIENT);
        glow.setGradientCenter(.25f, 0f);
        glow.setGradientRadius(getResources().getDisplayMetrics().widthPixels * .6f);
        glow.setColors(new int[]{s == 2 ? 0x1FFFFFFF : 0x12FFFFFF, 0x00FFFFFF});
        return new LayerDrawable(new Drawable[]{base, glow});
    }

    /** The knob in this state's colours, with a white ring while the remote is on it. */
    private Drawable knobFor(int s) {
        StateListDrawable k = new StateListDrawable();
        k.addState(new int[]{android.R.attr.state_focused}, knobShape(s, dp(3), 0xFFFFFFFF));
        k.addState(new int[]{}, knobShape(s, dp(1), 0x2EFFFFFF));
        return k;
    }

    private GradientDrawable knobShape(int s, int stroke, int strokeColor) {
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, KNOB[s]);
        g.setCornerRadius(dp(40));
        g.setStroke(stroke, strokeColor);
        return g;
    }

    /** The selected flag in the middle with a white ring, two smaller ones each side. */
    private void drawFlags() {
        flags.removeAllViews();
        for (int d = -2; d <= 2; d++) {
            int i = ((sel + d) % CODES.length + CODES.length) % CODES.length;
            int size = dp(d == 0 ? 60 : 34);
            FrameLayout cell = new FrameLayout(this);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(size, size);
            lp.setMargins(dp(10), 0, dp(10), 0);
            ImageView img = new ImageView(this);
            img.setImageResource(i == 0 ? R.drawable.ic_globe
                    : getResources().getIdentifier("flag_" + CODES[i], "drawable", getPackageName()));
            img.setForeground(getDrawable(R.drawable.gloss));
            img.setElevation(dp(4));
            img.setOutlineProvider(android.view.ViewOutlineProvider.BACKGROUND);
            GradientDrawable round = new GradientDrawable();
            round.setShape(GradientDrawable.OVAL);
            round.setColor(0xFF3A4152);
            img.setBackground(round);
            int pad = d == 0 ? dp(6) : 0;
            FrameLayout.LayoutParams ip = new FrameLayout.LayoutParams(-1, -1);
            ip.setMargins(pad, pad, pad, pad);
            cell.addView(img, ip);
            if (d == 0) cell.setForeground(getDrawable(R.drawable.ring));
            cell.setAlpha(d == 0 ? 1f : 0.55f);
            cell.setOnClickListener(v -> { // touch screens: tap a flag to pick it
                sel = i;
                prefs.edit().putString("country", CODES[sel]).apply();
                refresh();
            });
            flags.addView(cell, lp);
        }
    }

    private static String clock() {
        long t = (System.currentTimeMillis() - GommageVpn.since) / 1000;
        return String.format(Locale.US, "%02d:%02d:%02d", t / 3600, t / 60 % 60, t % 60);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
