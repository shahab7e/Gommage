package org.gommage.tv;

import android.app.Activity;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

/** Donation page: same wallets and words as the desktop app. Back on the remote returns home. */
public class SupportActivity extends Activity {
    static final int[] TABS = {R.id.btc, R.id.sol, R.id.bnb};
    static final int[] ICONS = {R.id.btcIcon, R.id.solIcon, R.id.bnbIcon};
    static final int[] QR = {R.drawable.qr_btc, R.drawable.qr_sol, R.drawable.qr_bnb};
    static final String[] NET = {"BITCOIN NETWORK", "SOLANA NETWORK", "BNB CHAIN (BEP-20)"};
    static final String[] ADDR = {"bc1qzlv8u8cc5205kwlk8s95xsz7eusl946hvze0uk",
            "AZW2vYQEMj1Cuw5tpGTJ3gPkQ2sDKMrxSoDKwFQGJx8M", "0xbC32f485567755977DDd13937534E72eD117B38E"};
    static final int[][] COIN = {{0xFFF7931A, 0xFFF7931A}, {0xFF9945FF, 0xFF14F195}, {0xFFF0B90B, 0xFFF0B90B}};

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.support);
        // desktop support page: amber light from the top over the app background
        GradientDrawable glow = new GradientDrawable();
        glow.setGradientType(GradientDrawable.RADIAL_GRADIENT);
        glow.setGradientCenter(.5f, 0f);
        glow.setGradientRadius(getResources().getDisplayMetrics().widthPixels * .5f);
        glow.setColors(new int[]{0x24F7B955, 0x00F7B955});
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF121419);
        findViewById(R.id.root).setBackground(new LayerDrawable(new Drawable[]{bg, glow}));

        for (int i = 0; i < 3; i++) {
            int c = i;
            GradientDrawable dot = new GradientDrawable(GradientDrawable.Orientation.TL_BR, COIN[i]);
            dot.setShape(GradientDrawable.OVAL);
            findViewById(ICONS[i]).setBackground(dot);
            View tab = findViewById(TABS[i]);
            tab.setOnFocusChangeListener((v, f) -> { if (f) show(c); }); // moving along the tabs switches the QR
            tab.setOnClickListener(v -> show(c));
        }
        show(0);
        findViewById(R.id.btc).requestFocus();
        View copy = findViewById(R.id.copy); // phone layout only; a TV has nothing to paste into
        if (copy != null) copy.setOnClickListener(v -> {
            String a = ((TextView) findViewById(R.id.addr)).getText().toString();
            ((android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE))
                    .setPrimaryClip(android.content.ClipData.newPlainText("Gommage wallet", a));
            ((TextView) copy).setText("Copied");
            copy.postDelayed(() -> ((TextView) copy).setText("Copy address"), 1500);
        });
    }

    private void show(int c) {
        for (int i = 0; i < 3; i++) findViewById(TABS[i]).setSelected(i == c);
        ((ImageView) findViewById(R.id.qr)).setImageResource(QR[c]);
        ((TextView) findViewById(R.id.net)).setText(NET[c]);
        ((TextView) findViewById(R.id.addr)).setText(ADDR[c]);
    }
}
