using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace LimitingFactor.LowLevel;

internal static partial class UnixDescriptorReceiver
{
    private const int SolSocket = 1;
    private const int ScmRights = 1;

    public static unsafe (int Tag, int FileDescriptor) Receive(
        Socket socket,
        CancellationToken cancellationToken)
    {
        var payload = new byte[sizeof(int)];
        var control = new byte[64];
        fixed (byte* payloadPointer = payload)
        fixed (byte* controlPointer = control)
        {
            var vector = new Iovec { Base = payloadPointer, Length = (nuint)payload.Length };
            var message = new MessageHeader
            {
                IoVector = &vector,
                IoVectorLength = 1,
                Control = controlPointer,
                ControlLength = (nuint)control.Length,
            };
            var result = recvmsg(socket.Handle, &message, 0);
            if (result <= 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (result == 0)
                {
                    throw new EndOfStreamException("The native sandbox helper closed its control connection before sending a FUSE descriptor.");
                }
                var error = Marshal.GetLastPInvokeError();
                if (socket.SafeHandle.IsClosed)
                {
                    throw new ObjectDisposedException(nameof(socket));
                }
                throw new IOException($"Receiving a FUSE descriptor failed with errno {error}.");
            }
            if (result != payload.Length || message.ControlLength < (nuint)sizeof(ControlMessageHeader))
            {
                throw new IOException("The native sandbox helper sent a malformed FUSE descriptor message.");
            }

            var header = (ControlMessageHeader*)controlPointer;
            if (header->Level != SolSocket || header->Type != ScmRights)
            {
                throw new IOException(
                    $"The native sandbox helper did not send a FUSE descriptor " +
                    $"(received {result} bytes, control length {message.ControlLength}, " +
                    $"header length {header->Length}, level {header->Level}, type {header->Type}).");
            }

            var dataOffset = Align((nuint)sizeof(ControlMessageHeader));
            var descriptor = *(int*)(controlPointer + dataOffset);
            return (BinaryPrimitives.ReadInt32LittleEndian(payload), descriptor);
        }
    }

    private static nuint Align(nuint length)
    {
        var alignment = (nuint)IntPtr.Size;
        return (length + alignment - 1) & ~(alignment - 1);
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct Iovec
    {
        public void* Base;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MessageHeader
    {
        public void* Name;
        public uint NameLength;
        private uint _padding;
        public Iovec* IoVector;
        public nuint IoVectorLength;
        public void* Control;
        public nuint ControlLength;
        public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ControlMessageHeader
    {
        public nuint Length;
        public int Level;
        public int Type;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial nint recvmsg(nint socket, MessageHeader* message, int flags);
}
