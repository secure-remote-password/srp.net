namespace System
{
	using System.Reflection;

#if NETCOREAPP_10

	public interface ICloneable
	{
		object Clone();
	}

	public static class TypeExtensions
	{
		public static Assembly GetAssembly(this Type type)
		{
			return type.GetTypeInfo().Assembly;
		}
	}

#else

	public static class TypeExtensions
	{
		public static Assembly GetAssembly(this Type type)
		{
			return type.Assembly;
		}
	}

#endif
}