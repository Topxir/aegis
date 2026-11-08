package org.aegis.messenger.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GuideTest {
    @Test
    fun stepsMatchDesktopOrder() {
        assertEquals(listOf(null, "menu", "lock", "tor", "search", "menu"), GUIDE_STEPS.map { it.target })
    }

    @Test
    fun stepping() {
        val n = GUIDE_STEPS.size
        assertEquals(1, Guide.after(0, n))
        assertEquals(n - 1, Guide.after(n - 2, n))
        assertNull(Guide.after(n - 1, n))
        assertEquals(0, Guide.before(0))
        assertEquals(2, Guide.before(3))
    }
}
