@file:Suppress("unused")

package net.corda.core

import java.io.InputStream
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.nio.file.*
import java.nio.file.attribute.FileAttribute
import java.time.Duration
import java.time.temporal.Temporal
import java.util.*
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.stream.IntStream
import java.util.stream.Stream
import java.util.stream.StreamSupport
import kotlin.reflect.KProperty




// Simple infix function to add back null safety that the JDK lacks:  timeA until timeB
infix fun Temporal.until(endExclusive: Temporal): Duration = Duration.between(this, endExclusive)

/** Like the + operator but throws an exception in case of integer overflow. */
infix fun Int.checkedAdd(b: Int) = Math.addExact(this, b)

/** Like the + operator but throws an exception in case of integer overflow. */
infix fun Long.checkedAdd(b: Long) = Math.addExact(this, b)

/** Allows you to write code like: Paths.get("someDir") / "subdir" / "filename" but using the Paths API to avoid platform separator problems. */
operator fun Path.div(other: String): Path = resolve(other)
operator fun String.div(other: String): Path = Paths.get(this) / other


/** Same as [Future.get] but with a more descriptive name, and doesn't throw [ExecutionException], instead throwing its cause */
fun <T> Future<T>.getOrThrow(timeout: Duration? = null): T {
    return try {
        if (timeout == null) get() else get(timeout.toNanos(), TimeUnit.NANOSECONDS)
    } catch (e: ExecutionException) {
        throw e.cause!!
    }
}

inline fun <R> Path.list(block: (Stream<Path>) -> R): R = Files.list(this).use(block)
fun Path.createDirectory(vararg attrs: FileAttribute<*>): Path = Files.createDirectory(this, *attrs)
fun Path.createDirectories(vararg attrs: FileAttribute<*>): Path = Files.createDirectories(this, *attrs)
fun Path.exists(vararg options: LinkOption): Boolean = Files.exists(this, *options)
fun Path.moveTo(target: Path, vararg options: CopyOption): Path = Files.move(this, target, *options)
fun Path.isRegularFile(vararg options: LinkOption): Boolean = Files.isRegularFile(this, *options)
fun Path.isDirectory(vararg options: LinkOption): Boolean = Files.isDirectory(this, *options)
val Path.size: Long get() = Files.size(this)
fun Path.deleteIfExists(): Boolean = Files.deleteIfExists(this)
inline fun <R> Path.read(vararg options: OpenOption, block: (InputStream) -> R): R {
    return Files.newInputStream(this, *options).use(block)
}
fun Path.readAll(): ByteArray = Files.readAllBytes(this)
fun Path.readAllLines(charset: Charset = StandardCharsets.UTF_8): List<String> = Files.readAllLines(this, charset)
inline fun <R> Path.readLines(charset: Charset = StandardCharsets.UTF_8, block: (Stream<String>) -> R): R {
    return Files.lines(this, charset).use(block)
}
fun Path.writeLines(lines: Iterable<CharSequence>, charset: Charset = StandardCharsets.UTF_8, vararg options: OpenOption): Path {
    return Files.write(this, lines, charset, *options)
}

fun InputStream.copyTo(target: Path, vararg options: CopyOption): Long = Files.copy(this, target, *options)

/**
 * A simple wrapper that enables the use of Kotlin's "val x by TransientProperty { ... }" syntax. Such a property
 * will not be serialized to disk, and if it's missing (or the first time it's accessed), the initializer will be
 * used to set it up. Note that the initializer will be called with the TransientProperty object locked.
 */
class TransientProperty<out T>(private val initializer: () -> T) {
    @Transient private var v: T? = null

    @Synchronized
    operator fun getValue(thisRef: Any?, property: KProperty<*>) = v ?: initializer().also { v = it }
}

private fun IntProgression.spliteratorOfInt(): Spliterator.OfInt {
    val kotlinIterator = iterator()
    val javaIterator = object : PrimitiveIterator.OfInt {
        override fun nextInt() = kotlinIterator.nextInt()
        override fun hasNext() = kotlinIterator.hasNext()
        override fun remove() = throw UnsupportedOperationException("remove")
    }
    val spliterator = Spliterators.spliterator(
            javaIterator,
            (1 + (last - first) / step).toLong(),
            Spliterator.SUBSIZED or Spliterator.IMMUTABLE or Spliterator.NONNULL or Spliterator.SIZED or Spliterator.ORDERED or Spliterator.SORTED or Spliterator.DISTINCT
    )
    return if (step > 0) spliterator else object : Spliterator.OfInt by spliterator {
        override fun getComparator() = Comparator.reverseOrder<Int>()
    }
}

fun IntProgression.stream(): IntStream = StreamSupport.intStream(spliteratorOfInt(), false)


